"""Fixed, journaled adoption of the pinned Hermes core service."""
from __future__ import annotations
import contextvars, fcntl, grp, hashlib, json, os, pwd, re, secrets, select, shlex, signal, stat, struct, subprocess, sys, tempfile, threading, time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import MappingProxyType
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
RESOURCES_SKILL_OVERLAYS=Path("/var/lib/hermes-installer/core-runtime/resources-skill-overlays")
ADAPTER_MIGRATION_BACKUP=Path("/var/lib/hermes-installer/core-runtime/adapter-migration-backup")
ADAPTER_UPDATE_BACKUPS=Path("/var/lib/hermes-installer/core-runtime/adapter-update-backups")
ADAPTER_UPDATE_COHORT=Path("/var/lib/hermes-installer/core-runtime/adapter-update-cohort.json")
NATIVE_ADOPTION_INGRESS_BACKUP=Path(
 "/var/lib/hermes-installer/core-runtime/native-adoption-ingress-backup.json")
_HELPER_IMPORT_STDOUT_LIMIT=32*1024
_HELPER_IMPORT_STDERR_LIMIT=16*1024
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

def _canonical_json(value):
 """Canonical ASCII JSON bytes shared with the fixed Resources importer."""
 return (json.dumps(value,sort_keys=True,separators=(",",":"),
                    ensure_ascii=True,allow_nan=False)+"\n").encode("ascii")

def _adapter_recipe_sha256(source,generation,unit_sha256,launcher_sha256):
 """Digest the closed source/unit/launcher tuple used by update and boot gates."""
 if (not isinstance(source,str) or not Path(source).is_absolute()
     or not isinstance(generation,str) or re.fullmatch(r"[0-9a-f]{64}",generation) is None
     or any(not isinstance(value,str) or re.fullmatch(r"[0-9a-f]{64}",value) is None
            for value in (unit_sha256,launcher_sha256))):
  raise CoreRuntimeError("adapter source recipe tuple is malformed")
 return hashlib.sha256(_canonical_json({"schema":1,"source":source,
  "generation":generation,"unit_sha256":unit_sha256,
  "launcher_sha256":launcher_sha256})).hexdigest()

_RESOURCES_PROFILE_SOURCE_SEAL = object()

# A helper-only generation rebind is prepared and consumed inside one root
# process.  The journal below is the recovery record; this short-lived object
# is only an in-process capability to consume that exact journaled cohort.
_SAME_MATERIALIZATION_SEAL = object()
_PREPARED_SAME_MATERIALIZATION = {}
_PREPARED_SAME_MATERIALIZATION_LOCK = threading.Lock()
_GUARDED_OLD_READ_SEAL=object()
_GUARDED_OLD_READ_ACTIVE={}
_GUARDED_OLD_READ_CONTEXT=contextvars.ContextVar("core_guarded_old_read",default=None)
_GUARDED_NEW_READ_CONTEXT=contextvars.ContextVar("core_guarded_new_read",default=None)
_ADAPTER_UPDATE_LOCK_HELD=contextvars.ContextVar("adapter_update_lock_held",default=False)
_ADAPTER_STARTUP_COHORT_CONTEXT=contextvars.ContextVar("adapter_startup_cohort_context",default=None)
_NATIVE_PLUGIN_TRANSITION_CONTEXT=contextvars.ContextVar("native_plugin_transition_context",default=None)
_NATIVE_PLUGIN_TRANSITION_STATE=contextvars.ContextVar("native_plugin_transition_state",default=None)
_INITIAL_PRIMARY_ADOPTION_CONTEXT=contextvars.ContextVar("initial_primary_adoption_context",default=None)
_ABSENT_DIGEST = "absent"
_ADAPTER_COHORT_PURPOSE="adapter-source-binding-cohort"
_ADAPTER_COHORT_PHASES={"prepared","resources-rebound","source-starting",
                        "bindings-verified","committed","rolling-back"}
_ADAPTER_COHORT_FIELDS={
 "schema","purpose","cohort_transaction_id","owner_uid","home_role","phase",
 "old_source","new_source","old_adapter_generation","new_adapter_generation",
 "old_core_source_generation","new_core_source_generation",
 "old_source_recipe_sha256","new_source_recipe_sha256","old_unit_sha256",
 "old_launcher_sha256","new_unit_sha256","new_launcher_sha256",
 "guarded_old_unit_sha256","guarded_old_recipe_sha256","old_process_identity_sha256",
 "old_journal_sha256","new_journal_sha256","old_resources_record_sha256",
 "pre_switch_resources_record_sha256","starting_journal_sha256",
 "starting_resources_record_sha256","new_resources_record_sha256",
 "old_artifact_sha256","new_artifact_sha256","owner_generation_backup_name",
 "primary_record_sha256","obsidian_registration_state","obsidian_registration_sha256",
 "obsidian_vault_tree_sha256","reconstruction","reconstruction_sha256",
 "initial_primary_transition","native_plugin_transition",
}
_ADAPTER_COHORT_LEGACY_FIELDS=_ADAPTER_COHORT_FIELDS-{"native_plugin_transition"}
_NATIVE_PLUGIN_FILES=("plugin.yaml","__init__.py")
_NATIVE_PLUGIN_BACKUP_NAMES={"plugin.yaml":"native-plugin-plugin.yaml",
                             "__init__.py":"native-plugin-__init__.py"}

@dataclass(frozen=True,slots=True)
class _NativeResourcesPluginTransitionContext:
 operation:str
 cohort_transaction_id:str|None
 old_adapter_generation:str
 new_adapter_generation:str
 plugin_selection_sha256:str
 old_members:object
 new_members:object
 installed_member_signatures:object
 transition_row:object
 backup_reference:object
 phase:str|None

def _validate_native_plugin_transition_row(value,cohort):
 """Validate the closed fixed-member transition DATA carried by one cohort."""
 if value is None: return
 fields={"schema","purpose","old_adapter_generation","new_adapter_generation",
         "plugin_selection_sha256","old_members","new_members"}
 if (type(value) is not dict or set(value)!=fields
     or type(value.get("schema")) is not int or value["schema"]!=1
     or value.get("purpose")!="fixed-native-resources-plugin"
     or value.get("old_adapter_generation")!=cohort.get("old_adapter_generation")
     or value.get("new_adapter_generation")!=cohort.get("new_adapter_generation")
     or value.get("plugin_selection_sha256") is None
     or re.fullmatch(r"[0-9a-f]{64}",str(value.get("plugin_selection_sha256",""))) is None):
  raise CoreRuntimeError("fixed native plugin transition row is malformed")
 for key in ("old_members","new_members"):
  members=value.get(key)
  if (type(members) is not dict or set(members)!=set(_NATIVE_PLUGIN_FILES)
      or any(type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}",digest) is None
             for digest in members.values())):
   raise CoreRuntimeError("fixed native plugin transition member map is malformed")
_INITIAL_PRIMARY_TRANSITION_FIELDS={
 "schema","purpose","state","prior_record_state","prior_soul_sha256",
 "prior_soul_signature","source_prompt_sha256","managed_block_sha256",
 "desired_soul_sha256","owner_separator_hex","owner_backup_sha256",
 "preparing_record_sha256","writing_record_sha256","adopted_record_sha256",
 "before_resources_record_sha256","after_resources_record_sha256",
}
_OVERLAY_RECONSTRUCTION_FIELDS={
 "schema","purpose","cohort_transaction_id","owner_uid","home_role","phase",
 "old_base_artifact_sha256","new_base_artifact_sha256",
 "old_composed_artifact_sha256","new_composed_artifact_sha256",
 "overlay_journal_sha256","overlay_contents",
 "base_non_installer_manifest_sha256","composed_non_installer_manifest_sha256",
 "materialized_tree_sha256","old_installed_journal_sha256",
 "new_installed_journal_sha256","old_discovery_sha256","new_discovery_sha256",
 "old_core_source_generation","new_core_source_generation",
 "old_source_recipe_sha256","new_source_recipe_sha256",
}

@dataclass(frozen=True, slots=True)
class GuardedOldReadCustody:
 purpose:str
 cohort_transaction_id:str
 cohort_sha256:str
 phase:str
 owner_uid:int
 home_role:str
 old_journal_sha256:str
 old_source:str
 old_adapter_generation:str
 old_core_source_generation:str
 old_unit_sha256:str
 old_launcher_sha256:str
 old_source_recipe_sha256:str
 guarded_old_unit_sha256:str
 guarded_old_recipe_sha256:str
 old_process_identity_sha256:str
 pid:int
 start_ticks:str
 boot_id:str
 expires_monotonic:float
 pidfd:int=field(repr=False,compare=False)
 _seal:object=field(repr=False,compare=False)

@dataclass(frozen=True, slots=True)
class GuardedNewReadCustody:
 purpose:str
 cohort_transaction_id:str
 cohort_sha256:str
 phase:str
 owner_uid:int
 home_role:str
 starting_journal_sha256:str
 starting_resources_record_sha256:str
 new_source:str
 new_adapter_generation:str
 new_core_source_generation:str
 new_unit_sha256:str
 new_launcher_sha256:str
 new_source_recipe_sha256:str
 process_identity_sha256:str
 pid:int
 start_ticks:str
 boot_id:str
 expires_monotonic:float
 pidfd:int=field(repr=False,compare=False)
 _seal:object=field(repr=False,compare=False)

_GUARDED_NEW_READ_SEAL=object()
_GUARDED_NEW_READ_ACTIVE={}
_INITIAL_PRIMARY_ADOPTION_SEAL=object()
_INITIAL_PRIMARY_ADOPTION_ACTIVE={}
_INITIAL_PRIMARY_ROLLBACK_SEAL=object()
_INITIAL_PRIMARY_ROLLBACK_ACTIVE={}
_STARTING_LIFECYCLE_OBSERVER_SEAL=object()
_STARTING_LIFECYCLE_OBSERVER_ACTIVE={}

@dataclass(frozen=True, slots=True)
class InitialPrimaryAdoptionCustody:
 """Root-only, in-process authority for one initial adoption in a source cohort."""
 transaction_id:str
 cohort_sha256:str
 source:str
 old_adapter_generation:str
 new_adapter_generation:str
 core_source_generation:str
 artifact_a1_sha256:str
 starting_journal_sha256:str
 starting_resources_record_sha256:str
 unit_sha256:str
 launcher_sha256:str
 source_recipe_sha256:str
 process_identity_sha256:str
 prior_soul_sha256:str
 prior_soul_signature:tuple[int,...]
 source_prompt_sha256:str
 managed_block_sha256:str
 desired_soul_sha256:str
 owner_separator_hex:str
 peer_pid:int
 peer_start_ticks:str
 boot_id:str
 invocation_id:str
 prior_record_sha256:str
 issued_monotonic:float
 deadline_monotonic:float
 expires_monotonic:float
 pidfd:int=field(repr=False,compare=False)
 _seal:object=field(repr=False,compare=False)

@dataclass(frozen=True)
class InitialPrimaryRollbackCustody:
 """One offline rollback of the exact initial-primary cohort stage."""
 schema:int
 purpose:str
 transaction_id:str
 cohort_sha256:str
 initial_transition_sha256:str
 recovery_snapshot_sha256:str
 owner_uid:int
 home_role:str
 source:str
 adapter_generation:str
 core_source_generation:str
 source_recipe_sha256:str
 unit_sha256:str
 launcher_sha256:str
 journal_sha256:str
 resources_record_sha256:str
 artifact_a1_sha256:str
 installed_journal_sha256:str
 installed_tree_sha256:str
 primary_stage_sha256:str
 prior_soul_sha256:str
 prior_soul_signature:tuple[int,...]
 desired_soul_sha256:str
 source_prompt_sha256:str
 managed_block_sha256:str
 owner_backup_sha256:str
 owner_backup_name:str
 expires_monotonic:float
 _seal:object=field(repr=False,compare=False)

@dataclass(frozen=True, slots=True)
class StartingLifecycleObserverCustody:
 """Root-selected live new-peer tuple for the private startup observer only."""
 cohort:object
 peer_pid:int
 peer_uid:int
 peer_gid:int
 peer_start_ticks:str
 boot_id:str
 invocation_id:str
 pidfd:int=field(repr=False,compare=False)
 expires_monotonic:float
 new_read:GuardedNewReadCustody=field(repr=False,compare=False)
 _seal:object=field(repr=False,compare=False)

@dataclass(frozen=True, slots=True)
class _StartingLifecycleObserverSession:
 custody:StartingLifecycleObserverCustody
 registry:object=field(repr=False,compare=False)
 rpc:object=field(repr=False,compare=False)

@dataclass(frozen=True, slots=True)
class _BaseOnlyReconstruction:
 new_composed_archive:bytes
 old_base_artifact_sha256:str
 new_base_artifact_sha256:str
 old_composed_artifact_sha256:str
 new_composed_artifact_sha256:str
 overlay_journal_sha256:str
 overlay_contents:tuple
 base_non_installer_manifest_sha256:str
 composed_non_installer_manifest_sha256:str
 materialized_tree_sha256:str
 shared_member_count:int

@contextmanager
def _adapter_update_lock():
 """Serialize source, owner-overlay and primary edits in one fixed lock order."""
 if os.geteuid()!=ROOT_UID:
  raise CoreRuntimeError("adapter source cohort requires the root actor")
 _ensure_dir(ADAPTER_UPDATE_BACKUPS,ROOT_UID,ROOT_UID,0o700)
 _ensure_dir(RESOURCES_SKILL_OVERLAYS,ROOT_UID,ROOT_UID,0o700)
 _ensure_dir(PRIMARY_PROMPT_BACKUPS,ROOT_UID,ROOT_UID,0o700)
 paths=sorted((ADAPTER_UPDATE_BACKUPS/"cohort.lock",
               RESOURCES_SKILL_OVERLAYS/"lock"),key=str)
 fds=[]; token=None
 try:
  for path in paths:
   fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,"O_NOFOLLOW",0),0o600)
   info=os.fstat(fd)
   if (not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or info.st_gid!=ROOT_UID
       or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
    os.close(fd); raise CoreRuntimeError("adapter update lock custody differs")
   fcntl.flock(fd,fcntl.LOCK_EX); fds.append(fd)
  token=_ADAPTER_UPDATE_LOCK_HELD.set(True)
  yield
 finally:
  if token is not None: _ADAPTER_UPDATE_LOCK_HELD.reset(token)
  for fd in reversed(fds):
   try: fcntl.flock(fd,fcntl.LOCK_UN)
   finally: os.close(fd)

@dataclass(frozen=True, slots=True)
class PreparedSameMaterializationTransition:
 schema:int
 purpose:str
 cohort_transaction_id:str
 owner_uid:int
 owner_home:str
 home_role:str
 old_source_generation:str
 new_source_generation:str
 old_adapter_generation:str
 new_adapter_generation:str
 old_source_recipe_sha256:str
 new_source_recipe_sha256:str
 old_artifact_sha256:str
 new_artifact_sha256:str
 old_manifest_sha256:str
 new_manifest_sha256:str
 shared_manifest_sha256:str
 shared_materialization_sha256:str
 shared_member_count:int
 old_base_artifact_sha256:str
 new_base_artifact_sha256:str
 old_composed_artifact_sha256:str
 new_composed_artifact_sha256:str
 overlay_journal_sha256:str
 overlay_contents:tuple[tuple[str,str],...]
 base_non_installer_manifest_sha256:str
 composed_non_installer_manifest_sha256:str
 materialized_tree_sha256:str
 installed_generation_journal_sha256:str
 installed_generation_custody_sha256:str
 old_installed_journal_sha256:str
 resources_record_sha256:str
 discovery_record_sha256:str
 old_discovery_sha256:str
 overlay_record_sha256:str
 primary_record_sha256:str
 soul_sha256:str
 soul_signature:tuple[int,...]
 owner_prefix_sha256:str
 owner_prefix_length:int
 owner_separator_hex:str
 managed_block_sha256:str
 prior_backup_sha256:str
 obsidian_registration_state:str
 obsidian_registration_sha256:str
 expires_monotonic:float
 _seal:object=field(repr=False,compare=False)

 @property
 def cohort_id(self):
  return self.cohort_transaction_id

def _seal_prepared_same_materialization_transition(*,current_check=None,**values):
 """Create the sole short-lived transition capability for the fixed updater."""
 if os.geteuid()!=ROOT_UID or current_check is None or not callable(current_check):
  raise CoreRuntimeError("same-materialization transition requires the root cohort producer")
 values={**values,"schema":1,"purpose":"helper-only",
         "owner_uid":1000,"owner_home":str(HERMES_HOME),
         "expires_monotonic":time.monotonic()+360.0,
         "_seal":_SAME_MATERIALIZATION_SEAL}
 try:
  prepared=PreparedSameMaterializationTransition(**values)
 except (TypeError,ValueError):
  raise CoreRuntimeError("same-materialization transition evidence is incomplete") from None
 if not _prepared_same_materialization_shape(prepared):
  raise CoreRuntimeError("same-materialization transition evidence is malformed")
 with _PREPARED_SAME_MATERIALIZATION_LOCK:
  expired=[key for key,state in _PREPARED_SAME_MATERIALIZATION.items()
           if time.monotonic()>=state["object"].expires_monotonic]
  for key in expired: _PREPARED_SAME_MATERIALIZATION.pop(key,None)
  _PREPARED_SAME_MATERIALIZATION[id(prepared)]={
   "object":prepared,"current_check":current_check,"claims":set(),
  }
 return prepared

def _prepared_same_materialization_shape(value):
 hashes=("old_source_generation","new_source_generation","old_source_recipe_sha256",
  "new_source_recipe_sha256","old_adapter_generation","new_adapter_generation",
  "old_artifact_sha256","new_artifact_sha256",
  "old_manifest_sha256","new_manifest_sha256","shared_manifest_sha256",
  "shared_materialization_sha256","installed_generation_journal_sha256",
  "installed_generation_custody_sha256","old_installed_journal_sha256",
  "resources_record_sha256","discovery_record_sha256","old_discovery_sha256",
  "old_base_artifact_sha256","new_base_artifact_sha256",
  "old_composed_artifact_sha256","new_composed_artifact_sha256",
  "base_non_installer_manifest_sha256","composed_non_installer_manifest_sha256",
  "materialized_tree_sha256")
 try:
  if (value.shared_member_count<1 or value.shared_member_count>20000
      or any(not isinstance(getattr(value,key),str)
             or re.fullmatch(r"[0-9a-f]{64}",getattr(value,key)) is None for key in hashes)
      or not isinstance(value.cohort_transaction_id,str)
      or re.fullmatch(r"[0-9a-f]{32}",value.cohort_transaction_id) is None
      or value.home_role!="jarvis-primary-home"
      or type(value.overlay_contents) is not tuple
      or len(value.overlay_contents)>396
      or tuple(sorted(value.overlay_contents))!=value.overlay_contents
      or any(type(row) is not tuple or len(row)!=2
             or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",row[0]) is None
             or re.fullmatch(r"[0-9a-f]{64}",row[1]) is None for row in value.overlay_contents)):
   return False
  for key in ("overlay_journal_sha256","overlay_record_sha256","primary_record_sha256",
              "obsidian_registration_sha256"):
   item=getattr(value,key)
   if item!=_ABSENT_DIGEST and re.fullmatch(r"[0-9a-f]{64}",str(item)) is None:
    return False
  if ((value.overlay_journal_sha256==_ABSENT_DIGEST)!=(not value.overlay_contents)
      or value.obsidian_registration_state not in {"absent","registered"}
      or (value.obsidian_registration_state=="absent")
          !=(value.obsidian_registration_sha256==_ABSENT_DIGEST)):
   return False
  if value.primary_record_sha256==_ABSENT_DIGEST:
   if (value.soul_sha256!=_ABSENT_DIGEST or value.owner_prefix_sha256!=_ABSENT_DIGEST
       or value.managed_block_sha256!=_ABSENT_DIGEST or value.prior_backup_sha256!=_ABSENT_DIGEST
       or value.owner_prefix_length!=0 or value.owner_separator_hex!=""
       or value.soul_signature!=()):
    return False
  elif (any(re.fullmatch(r"[0-9a-f]{64}",str(item)) is None for item in (
        value.soul_sha256,value.owner_prefix_sha256,value.managed_block_sha256,
        value.prior_backup_sha256))
        or type(value.owner_prefix_length) is not int or value.owner_prefix_length<0
        or type(value.soul_signature) is not tuple or len(value.soul_signature)!=9
        or any(type(part) is not int or part<0 for part in value.soul_signature)
        or not isinstance(value.owner_separator_hex,str)
        or len(value.owner_separator_hex)>16 or len(value.owner_separator_hex)%2):
   return False
  return True
 except (AttributeError,TypeError,ValueError):
  return False

def verify_prepared_same_materialization_transition(value,*,purpose="helper-only"):
 """Check exact in-process seal, purpose, deadline and producer currentness."""
 try:
  if (type(value) is not PreparedSameMaterializationTransition
      or value._seal is not _SAME_MATERIALIZATION_SEAL
      or value.purpose!=purpose or value.schema!=1
      or value.owner_uid!=1000 or value.owner_home!=str(HERMES_HOME)
      or not _prepared_same_materialization_shape(value)
      or time.monotonic()>=value.expires_monotonic):
   return False
  state=_PREPARED_SAME_MATERIALIZATION.get(id(value))
  if state is None or state.get("object") is not value:
   return False
  return bool(state["current_check"](value,purpose))
 except Exception:
  return False

def claim_prepared_same_materialization_step(value,*,step):
 """One-shot claim immediately before a fixed cohort side effect."""
 if step not in {"resources-import","primary-rebase"}:
  return False
 with _PREPARED_SAME_MATERIALIZATION_LOCK:
  if not verify_prepared_same_materialization_transition(value):
   return False
  state=_PREPARED_SAME_MATERIALIZATION.get(id(value))
  if state is None or step in state["claims"]:
   return False
  state["claims"].add(step)
  return True

def _read_adapter_update_cohort(*,allow_absent=False):
 try:
  raw=_projection_file(ADAPTER_UPDATE_COHORT,owner=ROOT_UID,group=ROOT_UID,
                       mode=0o400,maximum=128*1024)
 except FileNotFoundError:
  if allow_absent: return None,None
  raise CoreRuntimeError("adapter update cohort journal is missing") from None
 try:
  def unique(pairs):
   value={}
   for key,item in pairs:
    if key in value: raise ValueError
    value[key]=item
   return value
  row=json.loads(raw,object_pairs_hook=unique)
  if (type(row) is not dict or frozenset(row) not in {
       frozenset(_ADAPTER_COHORT_FIELDS),frozenset(_ADAPTER_COHORT_LEGACY_FIELDS)}
      or type(row.get("schema")) is not int or row["schema"]!=1
      or row.get("purpose")!=_ADAPTER_COHORT_PURPOSE
      or type(row.get("owner_uid")) is not int or row["owner_uid"]!=1000
      or row.get("home_role")!="jarvis-primary-home"
      or row.get("phase") not in _ADAPTER_COHORT_PHASES
      or not isinstance(row.get("cohort_transaction_id"),str)
      or re.fullmatch(r"[0-9a-f]{32}",row["cohort_transaction_id"]) is None):
   raise ValueError
  for key in ("old_adapter_generation","new_adapter_generation",
      "old_core_source_generation","new_core_source_generation",
      "old_source_recipe_sha256","new_source_recipe_sha256","old_unit_sha256",
      "old_launcher_sha256","new_unit_sha256","new_launcher_sha256",
      "guarded_old_unit_sha256","guarded_old_recipe_sha256","old_process_identity_sha256",
      "old_journal_sha256","pre_switch_resources_record_sha256","starting_journal_sha256",
      "starting_resources_record_sha256","new_journal_sha256","old_resources_record_sha256",
      "new_resources_record_sha256","old_artifact_sha256","new_artifact_sha256",
      "primary_record_sha256","obsidian_registration_sha256","obsidian_vault_tree_sha256"):
   if row[key] is not None and row[key]!=_ABSENT_DIGEST and re.fullmatch(r"[0-9a-f]{64}",str(row[key])) is None:
    raise ValueError
  future_hashes={"pre_switch_resources_record_sha256","starting_journal_sha256",
   "starting_resources_record_sha256","new_journal_sha256","new_resources_record_sha256"}
  phase=row["phase"]
  if any(row[key] is None for key in {
      "guarded_old_unit_sha256","guarded_old_recipe_sha256","old_process_identity_sha256",
      "old_journal_sha256","old_resources_record_sha256","old_unit_sha256","old_launcher_sha256",
      "old_source_recipe_sha256","old_adapter_generation","old_core_source_generation",
      "new_adapter_generation","new_core_source_generation","new_unit_sha256","new_launcher_sha256",
      "new_source_recipe_sha256","old_artifact_sha256","new_artifact_sha256"}):
   raise ValueError
  backup_name=row["owner_generation_backup_name"]
  if (not isinstance(backup_name,str)
      or backup_name!=".jarvis-resources-skills-helper-transition-"+row["cohort_transaction_id"]):
   raise ValueError
  if (phase=="prepared"
      and any(row[key] is not None for key in future_hashes)):
   raise ValueError
  if (phase=="resources-rebound"
      and (row["pre_switch_resources_record_sha256"] is None
       or any(row[key] is not None for key in ("starting_journal_sha256","starting_resources_record_sha256","new_journal_sha256","new_resources_record_sha256")))):
   raise ValueError
  if (phase in {"source-starting","bindings-verified"}
      and any(row[key] is None for key in ("pre_switch_resources_record_sha256","starting_journal_sha256","starting_resources_record_sha256"))):
   raise ValueError
  if phase=="committed" and any(row[key] is None for key in future_hashes): raise ValueError
  if phase=="rolling-back" and any(not (row[key] is None or isinstance(row[key],str)) for key in future_hashes):
   raise ValueError
  for key in ("old_source","new_source"):
   if not isinstance(row[key],str) or not Path(row[key]).is_absolute(): raise ValueError
  reconstruction=row["reconstruction"]
  base_only=(isinstance(reconstruction,dict)
             and reconstruction.get("purpose")=="helper-only-base-reconstruction")
  if (row["obsidian_registration_state"] not in {"absent","registered"}
      or (row["obsidian_registration_state"]=="absent")
          !=(row["obsidian_registration_sha256"]==_ABSENT_DIGEST)
      or type(reconstruction) is not dict
      or set(reconstruction)!=_OVERLAY_RECONSTRUCTION_FIELDS
      or type(reconstruction.get("schema")) is not int or reconstruction["schema"]!=1
      or reconstruction.get("purpose") not in {
       "helper-only-overlay-reconstruction","helper-only-base-reconstruction"}
      or reconstruction.get("cohort_transaction_id")!=row["cohort_transaction_id"]
      or reconstruction.get("owner_uid")!=1000
      or reconstruction.get("home_role")!="jarvis-primary-home"
      or reconstruction.get("phase")!=row["phase"]
      or reconstruction.get("new_core_source_generation")!=row["new_core_source_generation"]
      or reconstruction.get("old_core_source_generation")!=row["old_core_source_generation"]
      or reconstruction.get("new_source_recipe_sha256")!=row["new_source_recipe_sha256"]
      or reconstruction.get("old_source_recipe_sha256")!=row["old_source_recipe_sha256"]
      or reconstruction.get("old_composed_artifact_sha256")!=row["old_artifact_sha256"]
      or reconstruction.get("new_composed_artifact_sha256")!=row["new_artifact_sha256"]):
   raise ValueError
  for key in _OVERLAY_RECONSTRUCTION_FIELDS-{
      "schema","purpose","cohort_transaction_id","owner_uid","home_role","phase","overlay_contents"}:
   if base_only and key=="overlay_journal_sha256" and reconstruction[key]==_ABSENT_DIGEST:
    continue
   if reconstruction[key] is None and phase in {"prepared","rolling-back"} and key in {
       "new_installed_journal_sha256","new_discovery_sha256"}: continue
   if not isinstance(reconstruction[key],str) or re.fullmatch(r"[0-9a-f]{64}",reconstruction[key]) is None:
    raise ValueError
  contents=reconstruction["overlay_contents"]
  if (type(contents) is not list or len(contents)>396
      or any(type(item) is not dict or set(item)!={"skill_id","content_sha256"}
          or not isinstance(item.get("skill_id"),str)
          or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",item["skill_id"]) is None
          or not isinstance(item.get("content_sha256"),str)
          or re.fullmatch(r"[0-9a-f]{64}",item["content_sha256"]) is None for item in contents)
      or [item["skill_id"] for item in contents]!=sorted({item["skill_id"] for item in contents})):
   raise ValueError
  if base_only and (reconstruction["overlay_journal_sha256"]!=_ABSENT_DIGEST
      or contents
      or reconstruction["old_base_artifact_sha256"]!=reconstruction["old_composed_artifact_sha256"]
      or reconstruction["new_base_artifact_sha256"]!=reconstruction["new_composed_artifact_sha256"]
      or reconstruction["base_non_installer_manifest_sha256"]
          !=reconstruction["composed_non_installer_manifest_sha256"]):
   raise ValueError
  initial=row["initial_primary_transition"]
  if initial is not None:
   if (type(initial) is not dict or set(initial)!=_INITIAL_PRIMARY_TRANSITION_FIELDS
       or type(initial.get("schema")) is not int or initial.get("schema")!=1
       or initial.get("purpose")!="initial-primary-adoption"
       or initial.get("prior_record_state")!="absent"
       or initial.get("state") not in {"pending","preparing","writing","adopted","rolling-back"}
       or type(initial.get("prior_soul_signature")) is not list
       or len(initial["prior_soul_signature"])!=9
       or any(type(part) is not int or part<0 for part in initial["prior_soul_signature"])
       or not isinstance(initial.get("owner_separator_hex"),str)
       or len(initial["owner_separator_hex"])%2
       or len(initial["owner_separator_hex"])>4
       or any(c not in "0123456789abcdef" for c in initial["owner_separator_hex"])):
    raise ValueError
   for key in ("prior_soul_sha256","source_prompt_sha256","managed_block_sha256",
       "desired_soul_sha256","before_resources_record_sha256"):
    if not isinstance(initial.get(key),str) or re.fullmatch(r"[0-9a-f]{64}",initial[key]) is None:
     raise ValueError
   for key in ("owner_backup_sha256","preparing_record_sha256","writing_record_sha256",
       "adopted_record_sha256","after_resources_record_sha256"):
    item=initial.get(key)
    if item is not None and (not isinstance(item,str) or re.fullmatch(r"[0-9a-f]{64}",item) is None):
     raise ValueError
   progress_keys=("preparing_record_sha256","writing_record_sha256",
                  "adopted_record_sha256","after_resources_record_sha256")
   unwritten_rollback=(initial["state"]=="rolling-back"
       and all(initial.get(key) is None for key in progress_keys)
       and initial.get("owner_backup_sha256") is None)
   if unwritten_rollback:
    if row["primary_record_sha256"]!=_ABSENT_DIGEST:
     raise ValueError
    progress=(False,False,False,False)
   else:
    progress={
    "pending":(False,False,False,False),
    "preparing":(None,False,False,False),
    "writing":(True,True,False,None),
    "adopted":(True,True,True,True),
    "rolling-back":(True,initial.get("writing_record_sha256") is not None,
      initial.get("adopted_record_sha256") is not None,
      initial.get("after_resources_record_sha256") is not None),
    }[initial["state"]]
   for key,present in zip(progress_keys,progress):
    if present is not None and (initial.get(key) is not None)!=present:
     raise ValueError
   if (initial["state"] not in {"pending","preparing"}
       and not unwritten_rollback and initial.get("owner_backup_sha256") is None):
    raise ValueError
   if (initial["state"]=="preparing" and initial.get("preparing_record_sha256") is not None
       and initial.get("owner_backup_sha256") is None): raise ValueError
   if (phase in {"prepared","resources-rebound"} and initial["state"]!="pending"):
    raise ValueError
   if (phase in {"bindings-verified","committed"} and initial["state"]!="adopted"):
    raise ValueError
   if (initial["state"]=="adopted"
       and initial.get("after_resources_record_sha256")!=row.get("starting_resources_record_sha256")):
    raise ValueError
   if initial["state"]=="pending":
    if (row["primary_record_sha256"]!=_ABSENT_DIGEST
        or initial.get("owner_backup_sha256") is not None):
     raise ValueError
   if initial["state"]=="preparing":
    preparing_digest=initial.get("preparing_record_sha256")
    if preparing_digest is None:
     if (row["primary_record_sha256"]!=_ABSENT_DIGEST
         or initial.get("owner_backup_sha256") is not None):
      raise ValueError
    elif (row["primary_record_sha256"]!=preparing_digest
          or initial.get("owner_backup_sha256")!=initial["prior_soul_sha256"]):
     raise ValueError
   if initial["state"]=="writing" and (
       row["primary_record_sha256"]!=initial.get("writing_record_sha256")
       or initial.get("owner_backup_sha256")!=initial["prior_soul_sha256"]):
    raise ValueError
   if initial["state"]=="adopted" and (
       row["primary_record_sha256"]!=initial["adopted_record_sha256"]
       or initial.get("owner_backup_sha256")!=initial["prior_soul_sha256"]):
    raise ValueError
  if hashlib.sha256((json.dumps(reconstruction,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")).hexdigest()!=row["reconstruction_sha256"]:
   raise ValueError
  canonical=(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
  if raw!=canonical: raise ValueError
  if "native_plugin_transition" not in row:
   row={**row,"native_plugin_transition":None}
  _validate_native_plugin_transition_row(row.get("native_plugin_transition"),row)
  return row,raw
 except Exception:
  raise CoreRuntimeError("adapter update cohort journal is malformed or foreign") from None

def _write_adapter_update_cohort(row,*,expected_raw):
 if os.geteuid()!=ROOT_UID or type(row) is not dict or set(row)!=_ADAPTER_COHORT_FIELDS:
  raise CoreRuntimeError("adapter update cohort write is not root-selected")
 current=None
 try: current=_projection_file(ADAPTER_UPDATE_COHORT,owner=ROOT_UID,group=ROOT_UID,mode=0o400,maximum=128*1024)
 except FileNotFoundError: pass
 if current!=expected_raw: raise CoreRuntimeError("adapter update cohort changed before journal commit")
 raw=(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
 _atomic_replace(ADAPTER_UPDATE_COHORT,raw,0o400,ROOT_UID,ROOT_UID)
 _sync_directory(ADAPTER_UPDATE_COHORT.parent)
 if _projection_file(ADAPTER_UPDATE_COHORT,owner=ROOT_UID,group=ROOT_UID,mode=0o400,maximum=128*1024)!=raw:
  raise CoreRuntimeError("adapter update cohort journal readback differs")
 return raw

def _validate_adapter_update_cohort_journal(record,raw_journal):
 """Default `_journal` admission is final-commit only; scopes handle staged reads."""
 unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
 if b"LoadCredential=adapter-update-cohort:" not in unit:
  return None
 cohort,_raw=_read_adapter_update_cohort()
 if cohort["phase"]!="committed":
  raise CoreRuntimeError("adapter source binding cohort is not committed")
 journal_sha=hashlib.sha256(raw_journal).hexdigest()
 unit_sha=hashlib.sha256(unit).hexdigest()
 resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
 launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
 if (record.get("adapter_update_cohort_transaction_id")!=cohort["cohort_transaction_id"]
     or record.get("adapter_source")!=cohort["new_source"]
     or record.get("adapter_generation")!=cohort["new_adapter_generation"]
     or record.get("core_source_generation")!=cohort["new_core_source_generation"]
     or record.get("adapter_update_state")!="active"
     or journal_sha!=cohort["new_journal_sha256"]
     or hashlib.sha256(resources_raw).hexdigest()!=cohort["new_resources_record_sha256"]
     or unit_sha!=cohort["new_unit_sha256"]
     or hashlib.sha256(launcher).hexdigest()!=cohort["new_launcher_sha256"]
     or record.get("unit_sha256")!=cohort["new_unit_sha256"]
     or record.get("launcher_sha256")!=cohort["new_launcher_sha256"]):
  raise CoreRuntimeError("committed adapter cohort tuple differs from final source custody")
 transition=cohort.get("native_plugin_transition")
 if transition is not None:
  _validate_native_plugin_transition_row(transition,cohort)
  if _native_plugin_member_hashes(_read_installed_native_resources_plugin_members().members)!=transition["new_members"]:
   raise CoreRuntimeError("committed native plugin bytes differ from the selected cohort")
 if (cohort["new_source"]!=str(ADAPTER_SOURCE)
     or _core_source_generation()!=cohort["new_core_source_generation"]
     or cohort["new_source_recipe_sha256"]!=_adapter_recipe_sha256(
       cohort["new_source"],cohort["new_adapter_generation"],
       cohort["new_unit_sha256"],cohort["new_launcher_sha256"])):
  raise CoreRuntimeError("committed adapter source recipe differs from current reviewed source")
 _validate_adapter_generation_path(Path(cohort["old_source"]))
 return cohort

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

def _native_plugin_source_member_metadata_matches(info):
 return (stat.S_ISREG(info.st_mode) and info.st_uid==ROOT_UID and info.st_gid==ROOT_UID
  and not stat.S_IMODE(info.st_mode)&0o022 and info.st_nlink==1
  and 1<=info.st_size<=64*1024)

def _native_plugin_source_members(source):
 """Read the two fixed package members through immutable root-owned directories."""
 source=Path(source)
 _validate_adapter_generation_path(source)
 names={"plugin.yaml":"hermes_installer/components/resources_native_plugin_bundle/plugin.yaml",
        "__init__.py":"hermes_installer/components/resources_native_plugin_bundle/__init__.py"}
 result={}
 for member,relative in names.items():
  fd=os.open("/",os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
  try:
   parts=(source/relative).parts[1:]
   for component in parts[:-1]:
    child=os.open(component,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)
                   |getattr(os,"O_NOFOLLOW",0),dir_fd=fd)
    info=os.fstat(child)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=ROOT_UID
        or info.st_gid!=ROOT_UID or stat.S_IMODE(info.st_mode)&0o022):
     os.close(child); raise CoreRuntimeError("native plugin source directory custody differs")
    os.close(fd); fd=child
   file_fd=os.open(parts[-1],os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
                   |getattr(os,"O_CLOEXEC",0),dir_fd=fd)
   try:
    before=os.fstat(file_fd)
    if not _native_plugin_source_member_metadata_matches(before):
     raise CoreRuntimeError("native plugin source member custody differs")
    chunks=bytearray()
    while len(chunks)<before.st_size:
     block=os.read(file_fd,min(8192,before.st_size-len(chunks)))
     if not block: raise CoreRuntimeError("native plugin source member changed while read")
     chunks.extend(block)
    if os.read(file_fd,1): raise CoreRuntimeError("native plugin source member changed while read")
    after=os.fstat(file_fd); named=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
    signature=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                           item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
    if (signature(before)!=signature(after) or signature(before)!=signature(named)
        or stat.S_ISLNK(named.st_mode)):
     raise CoreRuntimeError("native plugin source member changed while read")
    result[member]=bytes(chunks)
   finally: os.close(file_fd)
  finally: os.close(fd)
 if set(result)!=set(_NATIVE_PLUGIN_FILES):
  raise CoreRuntimeError("native plugin source bundle is incomplete")
 return result

def _read_installed_native_resources_plugin_members():
 """Fixed root-only observation used by Core qualification and cohort CAS."""
 if os.geteuid()!=ROOT_UID:
  raise CoreRuntimeError("installed native plugin read requires Root")
 try:
  from .remote.native_plugin_bootstrap import (
   NativeResourcesPluginMemberSnapshot,read_installed_native_resources_plugin_members)
  snapshot=read_installed_native_resources_plugin_members()
  if (type(snapshot) is not NativeResourcesPluginMemberSnapshot
      or type(snapshot.members) is not MappingProxyType
      or type(snapshot.signatures) is not MappingProxyType
      or set(snapshot.members)!=set(_NATIVE_PLUGIN_FILES)
      or set(snapshot.signatures)!=set(_NATIVE_PLUGIN_FILES)):
   raise ValueError
  members=dict(snapshot.members); signatures=dict(snapshot.signatures)
  for name in _NATIVE_PLUGIN_FILES:
   value=members[name]; signature=signatures[name]
   if (type(value) is not bytes or not 1<=len(value)<=64*1024
       or type(signature) is not tuple or len(signature)!=9
       or any(type(part) is not int or part<0 for part in signature)
       or signature[2]!=0o444 or signature[3]!=ROOT_UID or signature[4]!=ROOT_UID
       or signature[5]!=1 or signature[6]!=len(value)):
    raise ValueError
  return snapshot
 except Exception:
  raise CoreRuntimeError("fixed installed native plugin pair is not safely readable") from None

def _native_plugin_member_hashes(members):
 if type(members) not in (dict,MappingProxyType) or set(members)!=set(_NATIVE_PLUGIN_FILES):
  raise CoreRuntimeError("native plugin member map is not the fixed pair")
 return {name:hashlib.sha256(members[name]).hexdigest() for name in _NATIVE_PLUGIN_FILES}

@contextmanager
def _native_plugin_transition_scope(operation):
 """Install one Core-derived context for bootstrap's fixed zero-argument API."""
 if (operation not in {"prepare","install","restore"} or os.geteuid()!=ROOT_UID
     or not _ADAPTER_UPDATE_LOCK_HELD.get()):
  raise CoreRuntimeError("native plugin transition requires the locked Root actor")
 state=_NATIVE_PLUGIN_TRANSITION_STATE.get()
 if type(state) is not dict: raise CoreRuntimeError("native plugin transition state is unavailable")
 if operation=="prepare":
  row=None; reference=None; phase=None; txid=None
  signatures=state["old_signatures"]
 else:
  cohort,raw=_read_adapter_update_cohort()
  row=cohort.get("native_plugin_transition")
  if row is None: raise CoreRuntimeError("cohort has no native plugin transition")
  reference=_adapter_update_backup_reference(cohort)
  phase=cohort["phase"]; txid=cohort["cohort_transaction_id"]
  if operation=="install" and phase!="resources-rebound":
   raise CoreRuntimeError("native plugin install is outside the resources-rebound phase")
  if operation=="restore" and phase!="rolling-back":
   raise CoreRuntimeError("native plugin restore is outside the rollback phase")
  if (_native_plugin_member_hashes(state["old_members"])!=row["old_members"]
      or _native_plugin_member_hashes(state["new_members"])!=row["new_members"]
      or state["plugin_selection_sha256"]!=row["plugin_selection_sha256"]):
   raise CoreRuntimeError("native plugin context differs from its journaled member pair")
  if reference!=_adapter_update_backup_reference(cohort):
   raise CoreRuntimeError("native plugin recovery backup reference changed")
  signatures=_read_installed_native_resources_plugin_members().signatures
 context=_NativeResourcesPluginTransitionContext(operation,txid,
  state["old_adapter_generation"],state["new_adapter_generation"],
  state["plugin_selection_sha256"],MappingProxyType(dict(state["old_members"])),
  MappingProxyType(dict(state["new_members"])),MappingProxyType(dict(signatures)),
  row,reference,phase)
 token=_NATIVE_PLUGIN_TRANSITION_CONTEXT.set(context)
 try:
  if _current_native_resources_plugin_transition() is not context:
   raise CoreRuntimeError("native plugin transition currentness could not be proven")
  yield context
 finally:
  _NATIVE_PLUGIN_TRANSITION_CONTEXT.reset(token)

def _current_native_resources_plugin_transition():
 """Return only the live Root-locked context after rechecking its exact joins."""
 context=_NATIVE_PLUGIN_TRANSITION_CONTEXT.get(); state=_NATIVE_PLUGIN_TRANSITION_STATE.get()
 if (type(context) is not _NativeResourcesPluginTransitionContext or type(state) is not dict
     or os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()):
  raise CoreRuntimeError("native plugin transition context is not current")
 if (context.old_adapter_generation!=state["old_adapter_generation"]
     or context.new_adapter_generation!=state["new_adapter_generation"]
     or context.plugin_selection_sha256!=state["plugin_selection_sha256"]
     or dict(context.old_members)!=state["old_members"]
     or dict(context.new_members)!=state["new_members"]
     or _core_source_generation()!=state["old_core_source_generation"]):
  raise CoreRuntimeError("native plugin transition source or owner selection changed")
 from .remote.core_gateway_inspector import _current_native_adapter_generation
 if _current_native_adapter_generation(deadline=time.monotonic()+20.0)!=context.new_adapter_generation:
  raise CoreRuntimeError("native plugin candidate generation changed")
 from .remote.native_plugin_bootstrap import verify_native_resources_plugin_selection
 selection=verify_native_resources_plugin_selection()
 if getattr(selection,"selection_sha256",None)!=context.plugin_selection_sha256:
  raise CoreRuntimeError("native plugin selection changed during transition")
 snapshot=_read_installed_native_resources_plugin_members()
 actual=dict(snapshot.members)
 if context.operation in {"prepare","install"}:
  if actual!=state["old_members"] or dict(snapshot.signatures)!=dict(context.installed_member_signatures):
   raise CoreRuntimeError("old native plugin pair changed before transition")
  if context.operation=="prepare":
   pidfd=state.get("old_pidfd")
   if pidfd is None:
    raise CoreRuntimeError("old native Core PIDFD is unavailable for plugin preparation")
   poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
   if (poller.poll(0)
       or not _owned_listener_pidfd(adapter_source=Path(state["old_source"]))):
    raise CoreRuntimeError("old native Core peer changed before plugin preparation")
  else:
   if (_run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active"
       or _run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip() not in {"","0"}
       or any(_owned_listener(adapter_source=Path(source))
              for source in (state["old_source"],state["new_source"]))):
    raise CoreRuntimeError("Core service was not stopped before native plugin installation")
   cohort,raw=_read_adapter_update_cohort()
   if (context.cohort_transaction_id!=cohort["cohort_transaction_id"]
       or context.phase!="resources-rebound" or context.transition_row!=cohort.get("native_plugin_transition")
       or context.backup_reference!=_adapter_update_backup_reference(cohort)
       or hashlib.sha256(raw).hexdigest()!=hashlib.sha256(state["cohort_raw"]).hexdigest()):
    raise CoreRuntimeError("native plugin install cohort changed before effect")
 else:
  if (set(actual)!=set(_NATIVE_PLUGIN_FILES)
      or any(actual[name] not in (state["old_members"][name],state["new_members"][name])
             for name in _NATIVE_PLUGIN_FILES)
      or _run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active"
      or _run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip() not in {"","0"}):
   raise CoreRuntimeError("current plugin pair or Core service is outside rollback closure")
  cohort,raw=_read_adapter_update_cohort()
  if (context.cohort_transaction_id!=cohort["cohort_transaction_id"]
      or context.phase!=cohort["phase"]
      or context.transition_row!=cohort.get("native_plugin_transition")
      or context.backup_reference!=_adapter_update_backup_reference(cohort)):
   raise CoreRuntimeError("native plugin restore cohort changed before effect")
  prior,contents=_read_adapter_update_backup(context.backup_reference)
  _check_adapter_cohort_rollback_currentness(cohort,prior,contents)
 return context

def _validate_native_plugin_transition_receipt(receipt,operation,context,installed_members):
 from .remote.native_plugin_bootstrap import NativeResourcesPluginTransitionReceipt
 try:
  if (type(receipt) is not NativeResourcesPluginTransitionReceipt or receipt.schema!=1
      or receipt.operation!=operation or receipt.cohort_transaction_id!=context.cohort_transaction_id
      or receipt.old_adapter_generation!=context.old_adapter_generation
      or receipt.new_adapter_generation!=context.new_adapter_generation
      or receipt.plugin_selection_sha256!=context.plugin_selection_sha256
      or dict(receipt.old_member_sha256)!=_native_plugin_member_hashes(context.old_members)
      or dict(receipt.new_member_sha256)!=_native_plugin_member_hashes(context.new_members)
      or dict(receipt.installed_member_sha256)!=_native_plugin_member_hashes(installed_members)
      or type(receipt.installed_member_signatures) is not MappingProxyType
      or set(receipt.installed_member_signatures)!=set(_NATIVE_PLUGIN_FILES)
      or any(type(receipt.installed_member_signatures[name]) is not tuple
             or len(receipt.installed_member_signatures[name])!=9
             or any(type(part) is not int or part<0
                    for part in receipt.installed_member_signatures[name])
             for name in _NATIVE_PLUGIN_FILES)):
   raise ValueError
  metadata={"schema":receipt.schema,"operation":receipt.operation,
   "cohort_transaction_id":receipt.cohort_transaction_id,
   "old_adapter_generation":receipt.old_adapter_generation,
   "new_adapter_generation":receipt.new_adapter_generation,
   "plugin_selection_sha256":receipt.plugin_selection_sha256,
   "old_member_sha256":dict(receipt.old_member_sha256),
   "new_member_sha256":dict(receipt.new_member_sha256),
   "installed_member_sha256":dict(receipt.installed_member_sha256),
   "installed_member_signatures":{name:list(receipt.installed_member_signatures[name])
    for name in _NATIVE_PLUGIN_FILES}}
  expected=hashlib.sha256(json.dumps(metadata,sort_keys=True,separators=(",",":"),
                                     ensure_ascii=True).encode("ascii")).hexdigest()
  if receipt.receipt_sha256!=expected: raise ValueError
  return dict(receipt.installed_member_signatures)
 except Exception:
  raise CoreRuntimeError("native plugin transition receipt is not an exact readback") from None

def _run_native_plugin_transition(operation):
 from .remote import native_plugin_bootstrap as bootstrap
 methods={"prepare":bootstrap.prepare_native_resources_plugin_transition,
          "install":bootstrap.install_native_resources_plugin_transition,
          "restore":bootstrap.restore_native_resources_plugin_transition}
 if operation not in methods: raise CoreRuntimeError("native plugin transition operation is not fixed")
 with _native_plugin_transition_scope(operation) as context:
  receipt=methods[operation]()
 snapshot=_read_installed_native_resources_plugin_members()
 expected=context.new_members if operation=="install" else context.old_members
 if dict(snapshot.members)!=dict(expected):
  raise CoreRuntimeError("native plugin fixed pair differs after transition readback")
 signatures=_validate_native_plugin_transition_receipt(receipt,operation,context,expected)
 if dict(snapshot.signatures)!=signatures:
  raise CoreRuntimeError("native plugin custody signature differs from transition receipt")
 return receipt

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

def _verified_resources_payload(_admin_receipt=None,*,repair_umask_dirs=False,
                                _prepared_transition=None):
 """Build a root-derived receipt and initiate a fresh pinned native-loader query."""
 from .registry import manual_jarvis_skills as native
 archive=native.build_manual_jarvis_skills_artifact()
 base_archive=archive
 # Owner edits are root-journaled overlays over exact pinned member IDs. The
 # source artifact remains byte-for-byte immutable and is rebuilt above.
 if _prepared_transition is None:
  overlay_record,overlay_contents,overlay_raw=_resources_skill_overlay_read()
  archive,artifact_sha=_current_resources_overlay_artifact(
   base_archive,overlay_record,overlay_contents,overlay_raw)
 else:
  overlay_record,overlay_contents,overlay_raw,reconstruction=_prepared_transition
  if hashlib.sha256(base_archive).hexdigest()!=reconstruction.new_base_artifact_sha256:
   raise CoreRuntimeError("prepared helper-only new base differs from the reviewed source")
  archive=reconstruction.new_composed_archive
  artifact_sha=reconstruction.new_composed_artifact_sha256
  if overlay_raw is None and (archive!=base_archive or overlay_contents):
   raise CoreRuntimeError("absent overlay cannot be represented as a reconstructed chain")
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

def _resources_skill_overlay_read():
 """Read the strict root journal and its content-addressed owner bytes."""
 path=RESOURCES_SKILL_OVERLAYS/"active.json"
 try: raw=_projection_file(path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
 except FileNotFoundError: raw=None
 from .registry import manual_jarvis_skills as native
 base_archive=native.build_manual_jarvis_skills_artifact(); base_sha=hashlib.sha256(base_archive).hexdigest()
 if raw is None: return {"schema":1,"base_artifact_sha256":base_sha,"skills":{}}, {}, None
 try:
  record=json.loads(raw)
  if (type(record) is not dict or set(record)!={"schema","base_artifact_sha256","skills"}
      or record.get("schema")!=1
      or re.fullmatch(r"[0-9a-f]{64}",str(record.get("base_artifact_sha256",""))) is None
      or type(record.get("skills")) is not dict or len(record["skills"])>396): raise ValueError
  contents={}
  for name,row in record["skills"].items():
   if (type(row) is not dict or set(row)!={"content_sha256","archive_sha256"}
       or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",name) is None
       or re.fullmatch(r"[0-9a-f]{64}",row["content_sha256"]) is None
       or re.fullmatch(r"[0-9a-f]{64}",row["archive_sha256"]) is None): raise ValueError
   content=_projection_file(RESOURCES_SKILL_OVERLAYS/(row["content_sha256"]+".bin"),
     owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
   if hashlib.sha256(content).hexdigest()!=row["content_sha256"]: raise ValueError
   contents[name]=content
  _current_resources_overlay_artifact(base_archive,record,contents,raw)
  return record,contents,raw
 except Exception:
  raise CoreRuntimeError("root Resources skill overlay journal is malformed or unverifiable") from None

def _current_resources_overlay_artifact(base_archive,record,contents,raw):
 """Derive the one current effective artifact, including exact committed rebinds."""
 from .registry import manual_jarvis_skills as native
 from .registry import resources_skill_overlay as transform
 base_sha=hashlib.sha256(base_archive).hexdigest()
 if raw is None:
  if record!={"schema":1,"base_artifact_sha256":base_sha,"skills":{}} or contents:
   raise CoreRuntimeError("absent Resources overlay differs from the current exact base")
  return base_archive,base_sha
 if record.get("base_artifact_sha256")==base_sha:
  archive,digests=transform.compose_overlays(base_archive,contents)
  if any(digests.get(name)!=row["archive_sha256"] for name,row in record["skills"].items()):
   raise CoreRuntimeError("Resources overlay chain differs from its exact current base")
  return archive,hashlib.sha256(archive).hexdigest()
 cohort,_raw=_read_adapter_update_cohort()
 old_scope=_GUARDED_OLD_READ_CONTEXT.get()
 if old_scope is not None and _validate_guarded_old_read(old_scope):
  if cohort["phase"]!="resources-rebound" or cohort.get("reconstruction") is None:
   raise CoreRuntimeError("staged Resources reconstruction is not ready for fixed root readback")
  return _resolve_staged_resources_reconstruction(
   native,transform,base_archive,record,contents,raw,cohort,starting=False)
 new_scope=_GUARDED_NEW_READ_CONTEXT.get()
 if new_scope is not None and _validate_guarded_new_read(new_scope):
  if cohort["phase"]!="source-starting" or cohort.get("reconstruction") is None:
   raise CoreRuntimeError("starting Resources reconstruction is not ready for fixed root readback")
  return _resolve_staged_resources_reconstruction(
   native,transform,base_archive,record,contents,raw,cohort,starting=True)
 if cohort["phase"]!="committed" or cohort.get("reconstruction") is None:
  raise CoreRuntimeError("Resources helper-only reconstruction is not committed")
 row=cohort["reconstruction"]
 root_journal=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 discovery_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
 installed_journal=_projection_file(HERMES_HOME/"skills"/native._GENERATION/native._OWNER_FILE,
  owner=1000,group=1000,mode=0o600,maximum=2*1024*1024)
 unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
 launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
 current=_journal()
 try:
  from hermes_installer.remote.core_gateway_inspector import _current_native_adapter_generation
  live_generation=_current_native_adapter_generation(deadline=time.monotonic()+35.0)
 except Exception:
  raise CoreRuntimeError("current native adapter source proof is unavailable") from None
 if (cohort.get("new_source")!=str(ADAPTER_SOURCE)
     or live_generation!=cohort.get("new_adapter_generation")
     or current.get("adapter_source")!=str(ADAPTER_SOURCE)
     or current.get("adapter_generation")!=cohort.get("new_adapter_generation")
     or current.get("core_source_generation")!=cohort.get("new_core_source_generation")
     or hashlib.sha256(root_journal).hexdigest()!=cohort.get("new_journal_sha256")
     or hashlib.sha256(discovery_raw).hexdigest()!=cohort.get("new_resources_record_sha256")
     or hashlib.sha256(installed_journal).hexdigest()!=row.get("new_installed_journal_sha256")
     or _adapter_recipe_sha256(str(ADAPTER_SOURCE),live_generation,
          hashlib.sha256(unit).hexdigest(),hashlib.sha256(launcher).hexdigest())
          !=cohort.get("new_source_recipe_sha256")
     or not _owned_unit_loaded()
     or not _owned_listener_pidfd(adapter_source=ADAPTER_SOURCE)):
  raise CoreRuntimeError("committed Resources source or installed generation custody is stale")
 old_base=_projection_file(RESOURCES_CAS/(row["old_base_artifact_sha256"]+".zip"),
  owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 old_composed=_projection_file(RESOURCES_CAS/(row["old_composed_artifact_sha256"]+".zip"),
  owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 if (hashlib.sha256(old_base).hexdigest()!=row["old_base_artifact_sha256"]
     or hashlib.sha256(old_composed).hexdigest()!=row["old_composed_artifact_sha256"]
     or base_sha!=row["new_base_artifact_sha256"]):
  raise CoreRuntimeError("committed Resources helper-only CAS bytes differ")
 context={key:row[key] for key in (
  "cohort_transaction_id","owner_uid","home_role","old_installed_journal_sha256",
  "new_installed_journal_sha256","old_discovery_sha256","new_discovery_sha256",
  "old_core_source_generation","new_core_source_generation",
  "old_source_recipe_sha256","new_source_recipe_sha256","phase")}
 result=transform.resolve_committed_helper_only_overlay_reconstruction(
  old_base,base_archive,old_composed,raw,contents,row,current_context=context)
 new_sha=result.new_composed_artifact_sha256
 if new_sha!=cohort["new_artifact_sha256"]:
  raise CoreRuntimeError("committed Resources reconstruction differs from the source cohort")
 return result.new_composed_archive,new_sha

def _resolve_staged_resources_reconstruction(native,transform,base_archive,
                                             record,contents,raw,cohort,*,starting):
 """Resolve A1 only inside the sealed root read scope before source stop."""
 old_row=cohort["reconstruction"]
 journal_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
 installed=_projection_file(HERMES_HOME/"skills"/native._GENERATION/native._OWNER_FILE,
  owner=1000,group=1000,mode=0o600,maximum=2*1024*1024)
 expected_journal=(cohort["starting_journal_sha256"] if starting else cohort["old_journal_sha256"])
 expected_resources=(cohort["starting_resources_record_sha256"] if starting
                     else cohort["pre_switch_resources_record_sha256"])
 if (hashlib.sha256(journal_raw).hexdigest()!=expected_journal
     or hashlib.sha256(resources_raw).hexdigest()!=expected_resources
     or hashlib.sha256(installed).hexdigest()!=old_row.get("new_installed_journal_sha256")
     or hashlib.sha256(raw).hexdigest()!=old_row.get("overlay_journal_sha256")):
  raise CoreRuntimeError("staged Resources root readback custody differs")
 old_base=_projection_file(RESOURCES_CAS/(old_row["old_base_artifact_sha256"]+".zip"),
  owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 old_composed=_projection_file(RESOURCES_CAS/(old_row["old_composed_artifact_sha256"]+".zip"),
  owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 if (hashlib.sha256(old_base).hexdigest()!=old_row["old_base_artifact_sha256"]
     or hashlib.sha256(old_composed).hexdigest()!=old_row["old_composed_artifact_sha256"]):
  raise CoreRuntimeError("staged Resources retained CAS bytes differ")
 if old_row.get("purpose")=="helper-only-base-reconstruction":
  result=_make_adapter_update_reconstruction(old_base,base_archive,old_composed,
   None,{},None,installed,resources_raw)
 else:
  result=transform.reconstruct_helper_only_overlay_transition(
   old_base,base_archive,old_composed,raw,contents)
 expected={"old_base_artifact_sha256":result.old_base_artifact_sha256,
  "new_base_artifact_sha256":result.new_base_artifact_sha256,
  "old_composed_artifact_sha256":result.old_composed_artifact_sha256,
  "new_composed_artifact_sha256":result.new_composed_artifact_sha256,
  "overlay_journal_sha256":result.overlay_journal_sha256,
  "overlay_contents":[{"skill_id":key,"content_sha256":sha} for key,sha in result.overlay_contents],
  "base_non_installer_manifest_sha256":result.base_non_installer_manifest_sha256,
  "composed_non_installer_manifest_sha256":result.composed_non_installer_manifest_sha256,
  "materialized_tree_sha256":result.materialized_tree_sha256,
  "new_installed_journal_sha256":hashlib.sha256(installed).hexdigest(),
  "old_discovery_sha256":cohort["old_resources_record_sha256"],
  "new_discovery_sha256":expected_resources,
  "old_core_source_generation":cohort["old_core_source_generation"],
  "new_core_source_generation":cohort["new_core_source_generation"],
  "old_source_recipe_sha256":cohort["old_source_recipe_sha256"],
  "new_source_recipe_sha256":cohort["new_source_recipe_sha256"]}
 if any(old_row.get(key)!=value for key,value in expected.items()):
  raise CoreRuntimeError("staged helper-only overlay reconstruction differs from the committed cohort")
 manifest,files=native._read_artifact(result.new_composed_archive,result.new_composed_artifact_sha256)
 if (hashlib.sha256(resources_raw).hexdigest()!=expected_resources
     or json.loads(resources_raw).get("artifact_sha256")!=result.new_composed_artifact_sha256):
  raise CoreRuntimeError("staged discovery record names a different composed artifact")
 _hash_generation_tree(HERMES_HOME,manifest,files,result.new_composed_artifact_sha256)
 return result.new_composed_archive,result.new_composed_artifact_sha256

def list_archived_resources_skill_versions(skill_id,core_source_generation):
 """List restorable owner versions after revalidating source, root files and hashes."""
 if (os.geteuid()!=ROOT_UID or not isinstance(skill_id,str)
     or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",skill_id) is None
     or not isinstance(core_source_generation,str)
     or re.fullmatch(r"[0-9a-f]{64}",core_source_generation) is None):
  raise CoreRuntimeError("Resources archive-list request is malformed")
 recover_resources_skill_overlay()
 current=read_current_resources_discovery(core_source_generation=core_source_generation)
 if current.get("resources_state")!="discovered": raise CoreRuntimeError("verified Resources source is unavailable")
 directory=RESOURCES_SKILL_OVERLAYS
 try: names=os.listdir(directory)
 except FileNotFoundError: return []
 candidates=sorted(name[:-5] for name in names if re.fullmatch(r"[0-9a-f]{64}\.json",name))
 if len(candidates)>4096: raise CoreRuntimeError("Resources archive inventory exceeds its bound")
 results=[]
 from .registry import resources_skill_overlay as transform
 for restore_id in candidates:
  raw=_projection_file(directory/(restore_id+".json"),owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=4096)
  try:
   metadata=json.loads(raw)
   if (type(metadata) is not dict or set(metadata)!={"schema","skill_id","content_sha256","restore_id"}
       or metadata.get("schema")!=1 or metadata.get("skill_id")!=skill_id
       or metadata.get("restore_id")!=restore_id
       or re.fullmatch(r"[0-9a-f]{64}",metadata.get("content_sha256","")) is None): continue
   content=_projection_file(directory/(metadata["content_sha256"]+".bin"),owner=ROOT_UID,
     group=ROOT_UID,mode=0o600,maximum=256*1024)
   if hashlib.sha256(content).hexdigest()!=metadata["content_sha256"]: continue
   from .registry import manual_jarvis_skills as native
   transform.build_effective_artifact(native.build_manual_jarvis_skills_artifact(),skill_id,content)
   results.append({"restore_id":restore_id,"sha256":metadata["content_sha256"]})
  except (CoreRuntimeError,ValueError,TypeError,KeyError):
   continue
 return results

def list_archived_resources_skills(core_source_generation):
 """Project all currently restorable Resources overlays in one bounded journal scan."""
 if (os.geteuid()!=ROOT_UID or not isinstance(core_source_generation,str)
     or re.fullmatch(r"[0-9a-f]{64}",core_source_generation) is None):
  raise CoreRuntimeError("Resources archive inventory request is malformed")
 recover_resources_skill_overlay()
 current=read_current_resources_discovery(core_source_generation=core_source_generation)
 if current.get("resources_state")!="discovered": raise CoreRuntimeError("verified Resources source is unavailable")
 directory=RESOURCES_SKILL_OVERLAYS
 try: names=os.listdir(directory)
 except FileNotFoundError: return []
 candidates=sorted(name[:-5] for name in names if re.fullmatch(r"[0-9a-f]{64}\.json",name))
 if len(candidates)>4096: raise CoreRuntimeError("Resources archive inventory exceeds its bound")
 from .registry import manual_jarvis_skills as native
 from .registry import resources_skill_overlay as transform
 base=native.build_manual_jarvis_skills_artifact()
 base_manifest,_=native._read_artifact(base,hashlib.sha256(base).hexdigest())
 pinned={row["skill_id"] for row in base_manifest["skill_members"]}
 output={}
 for restore_id in candidates:
  raw=_projection_file(directory/(restore_id+".json"),owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=4096)
  try:
   metadata=json.loads(raw); skill_id=metadata.get("skill_id") if type(metadata) is dict else None
   if (type(metadata) is not dict or set(metadata)!={"schema","skill_id","content_sha256","restore_id"}
       or metadata.get("schema")!=1 or metadata.get("restore_id")!=restore_id or skill_id not in pinned
       or re.fullmatch(r"[0-9a-f]{64}",metadata.get("content_sha256","")) is None): continue
   content=_projection_file(directory/(metadata["content_sha256"]+".bin"),owner=ROOT_UID,
     group=ROOT_UID,mode=0o600,maximum=256*1024)
   if hashlib.sha256(content).hexdigest()!=metadata["content_sha256"]: continue
   transform.build_effective_artifact(base,skill_id,content)
   output.setdefault(skill_id,[]).append({"restore_id":restore_id,"sha256":metadata["content_sha256"]})
  except (CoreRuntimeError,ValueError,TypeError,KeyError):
   continue
 return [{"skill_id":name,"versions":sorted(versions,key=lambda row:row["restore_id"])}
         for name,versions in sorted(output.items())]

def recover_resources_skill_overlay():
 """Resolve a crash-window transaction only when the exact old or new tree is present."""
 pending_path=RESOURCES_SKILL_OVERLAYS/"pending.json"
 try: raw=_projection_file(pending_path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=32*1024*1024)
 except FileNotFoundError: return False
 try:
  pending=json.loads(raw)
  if (type(pending) is not dict or set(pending)!={"schema","old_record","new_record","old_archive_sha256","new_archive_sha256","idempotency_key","request_sha256","result"}
      or pending.get("schema")!=1
      or re.fullmatch(r"[0-9a-f]{64}",pending.get("idempotency_key","")) is None
      or re.fullmatch(r"[0-9a-f]{64}",pending.get("request_sha256","")) is None
      or re.fullmatch(r"[0-9a-f]{64}",pending.get("old_archive_sha256","")) is None
      or re.fullmatch(r"[0-9a-f]{64}",pending.get("new_archive_sha256","")) is None
      or type(pending.get("result")) is not dict): raise ValueError
  old_archive=_projection_file(RESOURCES_CAS/(pending["old_archive_sha256"]+".zip"),owner=ROOT_UID,
    group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
  new_archive=_projection_file(RESOURCES_CAS/(pending["new_archive_sha256"]+".zip"),owner=ROOT_UID,
    group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
  if (hashlib.sha256(old_archive).hexdigest()!=pending["old_archive_sha256"]
      or hashlib.sha256(new_archive).hexdigest()!=pending["new_archive_sha256"]): raise ValueError
  from .registry import manual_jarvis_skills as native
  old_manifest,old_files=native._read_artifact(old_archive,pending["old_archive_sha256"])
  new_manifest,new_files=native._read_artifact(new_archive,pending["new_archive_sha256"])
  try:
   _hash_generation_tree(HERMES_HOME,old_manifest,old_files,pending["old_archive_sha256"])
   is_old=True
  except CoreRuntimeError:
   is_old=False
  if is_old:
   selected=pending["old_record"]
  else:
   _hash_generation_tree(HERMES_HOME,new_manifest,new_files,pending["new_archive_sha256"])
   selected=pending["new_record"]
  if selected is None: (RESOURCES_SKILL_OVERLAYS/"active.json").unlink(missing_ok=True)
  else: _atomic_replace(RESOURCES_SKILL_OVERLAYS/"active.json",
    (json.dumps(selected,sort_keys=True,separators=(",",":"))+"\n").encode("ascii"),0o600,ROOT_UID,ROOT_UID)
  _write_resources_discovery()
  if not is_old:
   _ensure_dir(RESOURCES_SKILL_OVERLAYS/"operations",ROOT_UID,ROOT_UID,0o700)
   operation={"schema":1,"request_sha256":pending["request_sha256"],"result":pending["result"]}
   _atomic_replace(RESOURCES_SKILL_OVERLAYS/"operations"/(pending["idempotency_key"]+".json"),
    (json.dumps(operation,sort_keys=True,separators=(",",":"))+"\n").encode("ascii"),0o600,ROOT_UID,ROOT_UID)
  pending_path.unlink()
  _sync_directory(pending_path.parent)
  return True
 except Exception:
  raise CoreRuntimeError("Resources skill overlay recovery needs operator review; no retry was attempted") from None

def _install_resources_skill_overlay_as_owner(next_archive,previous_archive,*,next_sha,previous_sha):
 """Run the exact native generation exchange as the Hermes home owner."""
 account=pwd.getpwnam("admin")
 runuser=_validated_executable(RUNUSER,{ROOT_UID})
 interpreter=_validated_executable(Path(sys.executable),{ROOT_UID,account.pw_uid})
 if runuser!=RUNUSER: raise CoreRuntimeError("fixed account-switch executable differs")
 argv=[str(runuser),"-u","admin","--",str(interpreter),"-m",
   "hermes_installer.registry.manual_jarvis_skills","install-overlay",
   "--home",str(HERMES_HOME),"--hermes-source",str(SOURCE),"--python",str(PYTHON),
   "--expected-sha256",next_sha,"--previous-sha256",previous_sha]
 framed=struct.pack(">QQ",len(next_archive),len(previous_archive))+next_archive+previous_archive
 env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":str(HOME),"HERMES_HOME":str(HERMES_HOME),
   "LANG":"C.UTF-8","PYTHONPATH":str(ADAPTER_SOURCE),"PYTHONNOUSERSITE":"1",
   "PYTHONDONTWRITEBYTECODE":"1"}
 try:
  result=subprocess.run(argv,input=framed,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
    timeout=600,env=env,check=False,close_fds=True)
 except (OSError,subprocess.TimeoutExpired,ValueError):
  raise CoreRuntimeError("native Resources overlay installation did not complete") from None
 if result.returncode!=0 or not isinstance(result.stdout,bytes) or len(result.stdout)>8*1024*1024:
  raise CoreRuntimeError("native Resources overlay installation or readback failed")
 try:
  receipt=json.loads(result.stdout.decode("utf-8","strict"))
 except (ValueError,UnicodeError):
  raise CoreRuntimeError("native Resources overlay receipt is malformed") from None
 if (type(receipt) is not dict or receipt.get("state")!="discovered"
     or receipt.get("discovered") is not True or receipt.get("artifact_sha256")!=next_sha
     or receipt.get("native_receipt",{}).get("loaded_skill_count")!=396):
  raise CoreRuntimeError("native Resources overlay receipt does not match the requested generation")
 return receipt

def admin_resources_skill(action,skill_id,*,expected_sha256,idempotency_key,core_source_generation,
                          content=None,restore_id=None):
 """Root-only CAS edit/archive/restore for one pinned Resources skill."""
 if (os.geteuid()!=ROOT_UID or action not in {"write","archive","restore"}
     or not isinstance(core_source_generation,str) or re.fullmatch(r"[0-9a-f]{64}",core_source_generation) is None
     or not isinstance(idempotency_key,str) or re.fullmatch(r"[0-9a-f]{64}",idempotency_key) is None
     or not isinstance(skill_id,str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",skill_id) is None
     or not isinstance(expected_sha256,str) or re.fullmatch(r"[0-9a-f]{64}",expected_sha256) is None):
  raise CoreRuntimeError("Resources skill request is malformed")
 _ensure_dir(RESOURCES_SKILL_OVERLAYS,ROOT_UID,ROOT_UID,0o700)
 lock_path=RESOURCES_SKILL_OVERLAYS/"lock"
 fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600)
 try:
  os.fchown(fd,ROOT_UID,ROOT_UID); os.fchmod(fd,0o600); fcntl.flock(fd,fcntl.LOCK_EX)
  if recover_resources_skill_overlay(): pass
  request_body=json.dumps({"action":action,"skill_id":skill_id,"expected_sha256":expected_sha256,
   "content_sha256":hashlib.sha256(content).hexdigest() if isinstance(content,bytes) else None,
   "restore_id":restore_id,"core_source_generation":core_source_generation},sort_keys=True,separators=(",",":" )).encode("ascii")
  request_sha=hashlib.sha256(request_body).hexdigest()
  operations_dir=RESOURCES_SKILL_OVERLAYS/"operations"
  _ensure_dir(operations_dir,ROOT_UID,ROOT_UID,0o700)
  operation_path=operations_dir/(idempotency_key+".json")
  try:
   prior=json.loads(_projection_file(operation_path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=8192))
   if prior.get("schema")!=1 or prior.get("request_sha256")!=request_sha or type(prior.get("result")) is not dict:
    raise CoreRuntimeError("Resources skill idempotency key was reused with different input")
   return prior["result"]
  except FileNotFoundError: pass
  before=read_current_resources_discovery(core_source_generation=core_source_generation)
  if before.get("resources_state")!="discovered": raise CoreRuntimeError("verified Resources source is unavailable")
  current_sha=before["artifact_sha256"]
  current_archive=_projection_file(RESOURCES_CAS/(current_sha+".zip"),owner=ROOT_UID,group=ROOT_UID,
    mode=0o600,maximum=16*1024*1024)
  from .registry import manual_jarvis_skills as native
  from .registry import resources_skill_overlay as transform
  current_manifest,current_files=native._read_artifact(current_archive,current_sha)
  row=next((item for item in current_manifest["skill_members"] if item["skill_id"]==skill_id),None)
  if row is None: raise CoreRuntimeError("skill is not pinned in the current Resources source")
  old_record,old_contents,old_raw=_resources_skill_overlay_read()
  current_content=current_files[row["archive_path"]]
  current_content_sha=hashlib.sha256(current_content).hexdigest()
  if current_content_sha!=expected_sha256: raise CoreRuntimeError("Resources skill changed; reload before editing")
  if action=="write":
   if not isinstance(content,bytes): raise CoreRuntimeError("Resources skill content is missing")
   next_content=content
  elif action=="archive":
   if skill_id not in old_contents: raise CoreRuntimeError("pinned Resources skills can be restored to base but not archived as owner edits")
   next_content=None
  else:
   if not isinstance(restore_id,str) or re.fullmatch(r"[0-9a-f]{64}",restore_id) is None:
    raise CoreRuntimeError("archived Resources skill version is unavailable")
   archive_meta=_projection_file(RESOURCES_SKILL_OVERLAYS/(restore_id+".json"),owner=ROOT_UID,
    group=ROOT_UID,mode=0o600,maximum=4096)
   metadata=json.loads(archive_meta)
   if (type(metadata) is not dict or set(metadata)!={"schema","skill_id","content_sha256","restore_id"}
       or metadata.get("schema")!=1 or metadata.get("skill_id")!=skill_id
       or metadata.get("restore_id")!=restore_id
       or re.fullmatch(r"[0-9a-f]{64}",metadata.get("content_sha256","")) is None):
    raise CoreRuntimeError("archived Resources skill version does not match")
   next_content=_projection_file(RESOURCES_SKILL_OVERLAYS/(metadata["content_sha256"]+".bin"),
    owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
   if hashlib.sha256(next_content).hexdigest()!=metadata["content_sha256"]: raise CoreRuntimeError("archived skill bytes changed")
  archived_id=None
  if action in {"write","archive","restore"} and skill_id in old_contents:
   archived_id=idempotency_key
   archived_sha=hashlib.sha256(old_contents[skill_id]).hexdigest()
   _atomic_replace(RESOURCES_SKILL_OVERLAYS/(archived_sha+".bin"),old_contents[skill_id],0o600,ROOT_UID,ROOT_UID)
   _atomic_replace(RESOURCES_SKILL_OVERLAYS/(archived_id+".json"),json.dumps({"schema":1,"skill_id":skill_id,
    "content_sha256":archived_sha,"restore_id":archived_id},sort_keys=True,separators=(",",":" )).encode("ascii"),0o600,ROOT_UID,ROOT_UID)
  next_contents=dict(old_contents)
  if next_content is None: next_contents.pop(skill_id,None)
  else:
   next_sha=hashlib.sha256(next_content).hexdigest()
   _atomic_replace(RESOURCES_SKILL_OVERLAYS/(next_sha+".bin"),next_content,0o600,ROOT_UID,ROOT_UID)
   next_contents[skill_id]=next_content
  base_archive=native.build_manual_jarvis_skills_artifact()
  next_archive,digests=transform.compose_overlays(base_archive,next_contents)
  next_sha=hashlib.sha256(next_archive).hexdigest()
  next_record={"schema":1,"base_artifact_sha256":hashlib.sha256(base_archive).hexdigest(),"skills":{
   name:{"content_sha256":hashlib.sha256(value).hexdigest(),"archive_sha256":digests[name]}
   for name,value in sorted(next_contents.items())}}
  _ensure_dir(RESOURCES_CAS,ROOT_UID,ROOT_UID,0o700)
  _atomic_replace(RESOURCES_CAS/(next_sha+".zip"),next_archive,0o600,ROOT_UID,ROOT_UID)
  result={"state":"discovered","skill_id":skill_id,"sha256":hashlib.sha256(next_content if next_content is not None else transform.pinned_skill_bytes(base_archive,skill_id)).hexdigest(),
   "source_generation":hashlib.sha256((core_source_generation+"\0"+next_sha).encode()).hexdigest(),
   "recovery_id":archived_id,"effective_readback":True,"artifact_sha256":next_sha}
  pending={"schema":1,"old_record":old_record if old_contents else None,"new_record":next_record,
   "old_archive_sha256":current_sha,"new_archive_sha256":next_sha,"idempotency_key":idempotency_key,
   "request_sha256":request_sha,"result":result}
  _atomic_replace(RESOURCES_SKILL_OVERLAYS/"pending.json",
   json.dumps(pending,sort_keys=True,separators=(",",":" )).encode("ascii"),0o600,ROOT_UID,ROOT_UID)
  try:
   _install_resources_skill_overlay_as_owner(next_archive,current_archive,
    next_sha=next_sha,previous_sha=current_sha)
   _atomic_replace(RESOURCES_SKILL_OVERLAYS/"active.json",
    (json.dumps(next_record,sort_keys=True,separators=(",",":"))+"\n").encode("ascii"),0o600,ROOT_UID,ROOT_UID)
   receipt=_write_resources_discovery()
   _atomic_replace(operation_path,(json.dumps({"schema":1,"request_sha256":request_sha,"result":result},
    sort_keys=True,separators=(",",":"))+"\n").encode("ascii"),0o600,ROOT_UID,ROOT_UID)
   (RESOURCES_SKILL_OVERLAYS/"pending.json").unlink(missing_ok=True); _sync_directory(RESOURCES_SKILL_OVERLAYS)
  except CoreRuntimeError:
   recover_resources_skill_overlay()
   raise
  except Exception:
   recover_resources_skill_overlay()
   raise CoreRuntimeError("native Resources skill replacement or readback failed") from None
  return {**result,"artifact_sha256":receipt["artifact_sha256"]}
 finally:
  fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)

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
  overlay_record,overlay_contents,overlay_raw=_resources_skill_overlay_read()
  effective_archive,effective_sha=_current_resources_overlay_artifact(
   native.build_manual_jarvis_skills_artifact(),overlay_record,overlay_contents,overlay_raw)
  if effective_sha!=artifact_sha or effective_archive!=archive:
   return {**pending,"resources_state":"stale"}
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
def _launcher(adapter_source=None):
 # The fixed new recipe uses this checkout; recovery recipes may only name
 # the exact source already present in the root-owned update backup.
 source=Path(adapter_source) if adapter_source is not None else ADAPTER_SOURCE
 pythonpath=shlex.quote(f"{SOURCE}:{source}")
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
_ADAPTER_UPDATE_BACKUP_MEMBERS=("journal.json","unit","launcher","plugin-selection.json",
 "resources-record.json","overlay-record.json","primary-record.json",
 "obsidian-registration.json","cohort.json")

def _journal_adapter_backup_generation(record):
 reference=record.get("adapter_update_backup") if type(record) is dict else None
 generation=reference.get("source_generation") if type(reference) is dict else None
 if not isinstance(generation,str) or re.fullmatch(r"[0-9a-f]{64}",generation) is None:
  raise CoreRuntimeError("journaled adapter update backup generation is unavailable")
 return generation

def _core_start_guard_code(adapter_source=None,cohort_gate=False,backup_generation=None):
 """Validate systemd's journal snapshot and the exact fixed service recipe."""
 expected_source=str(adapter_source or ADAPTER_SOURCE)
 base_code=("import hashlib,json,os,stat; "
         f"service={SERVICE!r}; source={expected_source!r}; "
         "base=os.environ.get('CREDENTIALS_DIRECTORY',''); "
         "jp=os.path.join(base,'core-ownership-journal'); tp=os.path.join(base,'hermes-session-token'); "
         "js=os.stat(jp,follow_symlinks=False); ts=os.stat(tp,follow_symlinks=False); "
         "ok=(stat.S_ISREG(js.st_mode) and js.st_nlink==1 and not stat.S_IMODE(js.st_mode)&0o222 and 0<js.st_size<=65536 "
         "and stat.S_ISREG(ts.st_mode) and ts.st_nlink==1 and not stat.S_IMODE(ts.st_mode)&0o222 and 0<ts.st_size<=65536); "
         "raw=open(jp,'rb').read(65537) if ok else b''; token=open(tp,'rb').read(65537) if ok else b''; "
         "d=json.loads(raw) if len(raw)==js.st_size else {}; "
         "valid=lambda p,uid,gid,mode,digest: (lambda s,b: stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)==(uid,gid,mode,1) and 0<s.st_size<=262144 and len(b)==s.st_size and hashlib.sha256(b).hexdigest()==digest)(os.stat(p,follow_symlinks=False),open(p,'rb').read(262145)); "
         "state=d.get('adapter_update_state'); starting=(state=='starting'); "
         "source_ok=(d.get('adapter_migration_state')=='active' and d.get('adapter_source')==source); "
         "hex64=lambda x: isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x); "
         "backup=d.get('adapter_update_backup'); backup_ok=(isinstance(backup,dict) and hex64(backup.get('source_generation')) and backup.get('path')=="+repr(str(ADAPTER_UPDATE_BACKUPS))+"+'/'+backup.get('source_generation','')); "
         "native_ok=(d.get('adapter_migration_state') is None or (source_ok and hex64(d.get('adapter_generation')) and hex64(d.get('core_source_generation')) and hex64(d.get('plugin_selection_sha256')))); "
         "starting_ok=(source_ok and d.get('adapter_update_target_source')==source and d.get('adapter_generation')==d.get('adapter_update_target_generation') and hex64(d.get('adapter_update_staged_plugin_sha256')) and d.get('adapter_update_previous_source')!=source and backup_ok); "
         "active_update_ok=(backup_ok and d.get('adapter_update_previous_source')!=source); "
         "phase_ok=(native_ok and (state is None or (state=='starting' and starting_ok) or (state=='active' and active_update_ok))); "
         "files=(("+repr(str(UNIT))+",0,0,0o644,d.get('unit_sha256')),("+repr(str(LAUNCHER))+",0,0,0o755,d.get('launcher_sha256'))); "
         "ok=(ok and os.geteuid()==1000 and len(raw)==js.st_size and token and hashlib.sha256(token).hexdigest()==d.get('token_sha256') and d.get('schema')==1 and d.get('service')==service and d.get('state') in ('installed','active') and d.get('adapter_migration_state') in (None,'active') and phase_ok and all(valid(p,u,g,m,h) for p,u,g,m,h in files)); ")
 if cohort_gate:
  if not isinstance(backup_generation,str) or re.fullmatch(r"[0-9a-f]{64}",backup_generation) is None:
   raise CoreRuntimeError("cohort service recipe requires its fixed retained-backup generation")
  # Keep systemd's credential names fixed and pass only root-owned files from
  # the immutable generation directory. The service still runs as admin.
  gate_code=("import hashlib,json,os,stat; "
    "cp=os.path.join(base,'adapter-update-cohort'); rp=os.path.join(base,'resources-discovery'); "
    "cs=os.stat(cp,follow_symlinks=False); rs=os.stat(rp,follow_symlinks=False); "
    "cr=open(cp,'rb').read(131073); rr=open(rp,'rb').read(16385); "
    "c=json.loads(cr); r=json.loads(rr); "
    "keys={'schema','purpose','cohort_transaction_id','owner_uid','home_role','phase','old_source','new_source','old_adapter_generation','new_adapter_generation','old_core_source_generation','new_core_source_generation','old_source_recipe_sha256','new_source_recipe_sha256','old_unit_sha256','old_launcher_sha256','new_unit_sha256','new_launcher_sha256','guarded_old_unit_sha256','guarded_old_recipe_sha256','old_process_identity_sha256','old_journal_sha256','new_journal_sha256','old_resources_record_sha256','pre_switch_resources_record_sha256','starting_journal_sha256','starting_resources_record_sha256','new_resources_record_sha256','old_artifact_sha256','new_artifact_sha256','owner_generation_backup_name','primary_record_sha256','obsidian_registration_state','obsidian_registration_sha256','obsidian_vault_tree_sha256','reconstruction','reconstruction_sha256','initial_primary_transition'}; "
    "canonical=lambda v:(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\\n').encode('ascii'); "
    "recipe=lambda s,g,u,l:hashlib.sha256(canonical({'schema':1,'source':s,'generation':g,'unit_sha256':u,'launcher_sha256':l})).hexdigest(); "
    "cp_ok=(stat.S_ISREG(cs.st_mode) and stat.S_IMODE(cs.st_mode)==0o400 and cs.st_nlink==1 and 0<len(cr)==cs.st_size<=131072); "
    "rp_ok=(stat.S_ISREG(rs.st_mode) and stat.S_IMODE(rs.st_mode)==0o400 and rs.st_nlink==1 and 0<len(rr)==rs.st_size<=16384); "
    "phase=c.get('phase'); starting=phase in ('source-starting','bindings-verified'); expected_j=c.get('starting_journal_sha256') if starting else c.get('new_journal_sha256'); expected_r=c.get('starting_resources_record_sha256') if starting else c.get('new_resources_record_sha256'); "
    "reconstruction=c.get('reconstruction'); reconstruction_ok=(isinstance(reconstruction,dict) and hashlib.sha256(canonical(reconstruction)).hexdigest()==c.get('reconstruction_sha256') and reconstruction.get('cohort_transaction_id')==c.get('cohort_transaction_id') and reconstruction.get('phase')==phase and reconstruction.get('old_core_source_generation')==c.get('old_core_source_generation') and reconstruction.get('new_core_source_generation')==c.get('new_core_source_generation') and reconstruction.get('old_source_recipe_sha256')==c.get('old_source_recipe_sha256') and reconstruction.get('new_source_recipe_sha256')==c.get('new_source_recipe_sha256')); "
    "backup=d.get('adapter_update_backup'); backup_members="+repr(list(_ADAPTER_UPDATE_BACKUP_MEMBERS))+"; "
    "backup_generation="+repr(backup_generation)+"; "
    "backup_manifest_name='adapter-backup-manifest'; "
    "backup_manifest_path=os.path.join(base,backup_manifest_name); backup_manifest_stat=os.stat(backup_manifest_path,follow_symlinks=False); backup_raw=open(backup_manifest_path,'rb').read(4097); "
    "backup_files=(backup.get('files') if isinstance(backup,dict) else None); "
    "backup_ok=(isinstance(backup,dict) and backup.get('source_generation')==backup_generation and backup.get('path')=="+repr(str(ADAPTER_UPDATE_BACKUPS))+"+'/'+backup_generation and set(backup_files or {})==set(backup_members) and backup_raw==canonical(backup_files) and stat.S_ISREG(backup_manifest_stat.st_mode) and (backup_manifest_stat.st_uid,backup_manifest_stat.st_gid)==(1000,1000) and stat.S_IMODE(backup_manifest_stat.st_mode)==0o400 and backup_manifest_stat.st_nlink==1 and len(backup_raw)==backup_manifest_stat.st_size); "
    "backup_valid=lambda n,h:(lambda p,s,b:stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid)==(1000,1000) and stat.S_IMODE(s.st_mode)==0o400 and s.st_nlink==1 and 0<s.st_size<=262144 and len(b)==s.st_size and hashlib.sha256(b).hexdigest()==h)(os.path.join(base,"+repr("adapter-backup-")+"+n.replace('.json','').replace('.','-')),os.stat(os.path.join(base,"+repr("adapter-backup-")+"+n.replace('.json','').replace('.','-')),follow_symlinks=False),open(os.path.join(base,"+repr("adapter-backup-")+"+n.replace('.json','').replace('.','-')),'rb').read(262145)); "
    "backup_ok=backup_ok and all(backup_valid(name,backup_files.get(name)) for name in backup_members) and hashlib.sha256(backup_raw).hexdigest()==hashlib.sha256(canonical(backup_files)).hexdigest(); "
    "initial=c.get('initial_primary_transition'); initial_ok=(initial is None or (isinstance(initial,dict) and initial.get('purpose')=='initial-primary-adoption' and initial.get('prior_record_state')=='absent' and initial.get('state') in ('pending','adopted') and ((initial.get('state')=='pending' and c.get('primary_record_sha256')=='absent' and initial.get('owner_backup_sha256') is None) or (initial.get('state')=='adopted' and initial.get('adopted_record_sha256')==c.get('primary_record_sha256') and initial.get('after_resources_record_sha256')==hashlib.sha256(rr).hexdigest())))); "
    "cohort_ok=(backup_ok and cp_ok and rp_ok and initial_ok and canonical(c)==cr and set(c)==keys and c.get('schema')==1 and c.get('purpose')=='adapter-source-binding-cohort' and c.get('owner_uid')==1000 and c.get('home_role')=='jarvis-primary-home' and c.get('owner_generation_backup_name')=='.jarvis-resources-skills-helper-transition-'+c.get('cohort_transaction_id') and phase in ('source-starting','bindings-verified','committed') and reconstruction_ok and c.get('new_source')==source and c.get('new_adapter_generation')==d.get('adapter_generation') and c.get('new_core_source_generation')==d.get('core_source_generation') and c.get('new_source_recipe_sha256')==recipe(source,d.get('adapter_generation'),d.get('unit_sha256'),d.get('launcher_sha256')) and expected_j==hashlib.sha256(raw).hexdigest() and expected_r==hashlib.sha256(rr).hexdigest() and r.get('core_ownership_sha256')==hashlib.sha256(raw).hexdigest() and r.get('core_source_generation')==c.get('new_core_source_generation') and r.get('artifact_sha256')==c.get('new_artifact_sha256') and d.get('adapter_update_cohort_transaction_id')==c.get('cohort_transaction_id') and d.get('adapter_update_target_source')==source and d.get('adapter_update_target_generation')==d.get('adapter_generation') and ((starting and d.get('adapter_update_state')=='starting') or (phase=='committed' and d.get('adapter_update_state')=='active')) and hashlib.sha256(open('/etc/systemd/system/hermes-jarvis-core.service','rb').read()).hexdigest()==c.get('new_unit_sha256') and hashlib.sha256(open('/usr/local/libexec/hermes-jarvis-core-launcher','rb').read()).hexdigest()==c.get('new_launcher_sha256')); "
    "ok=ok and cohort_ok; ")
 else:
  gate_code=""
 return base_code+gate_code+"raise SystemExit(0 if ok else 1)"
def _unit(*,startup_guard=True,adapter_source=None,cohort_gate=False,backup_generation=None):
 a=pwd.getpwnam("admin")
 if a.pw_uid!=1000 or a.pw_gid!=1000 or a.pw_dir!="/home/admin": raise CoreRuntimeError("admin identity mismatch")
 guard=""
 if startup_guard:
  guard=(f'ExecStartPre={PYTHON} -I -S -c "{_core_start_guard_code(adapter_source,cohort_gate,backup_generation)}"\n'
         f'LoadCredential=core-ownership-journal:{JOURNAL}\n')
  if cohort_gate:
   guard+=(f'LoadCredential=adapter-update-cohort:{ADAPTER_UPDATE_COHORT}\n'
           f'LoadCredential=resources-discovery:{RESOURCES_RECORD}\n')
   for name in _ADAPTER_UPDATE_BACKUP_MEMBERS:
    credential="adapter-backup-"+name.removesuffix(".json").replace(".","-")
    guard+=(f'LoadCredential={credential}:{ADAPTER_UPDATE_BACKUPS/backup_generation/name}\n')
   guard+=(f'LoadCredential=adapter-backup-manifest:{ADAPTER_UPDATE_BACKUPS/backup_generation/"manifest.json"}\n')
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
{guard}LoadCredential=hermes-session-token:{TOKEN}
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
 raw_journal=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 old_scope=_GUARDED_OLD_READ_CONTEXT.get(); new_scope=_GUARDED_NEW_READ_CONTEXT.get()
 guarded_old=old_scope is not None and _validate_guarded_old_read(old_scope)
 guarded_new=new_scope is not None and _validate_guarded_new_read(new_scope)
 if (old_scope is not None and not guarded_old) or (new_scope is not None and not guarded_new):
  raise CoreRuntimeError("fixed source readback custody is stale")
 try: d=json.loads(raw_journal)
 except (OSError,ValueError) as e: raise CoreRuntimeError("core journal invalid") from e
 if d.get("schema")!=1 or d.get("service")!=SERVICE or d.get("state") not in {"preparing","installed","active","retiring"}: raise CoreRuntimeError("core journal identity unsupported")
 if d["state"] in {"installed","active","retiring"}:
  for p,k,uid,gid,mode in FILE_CONTRACT:
   if not p.exists() and not p.is_symlink() and d["state"]=="retiring": continue
   if not p.is_file() or p.is_symlink(): raise CoreRuntimeError("owned service file changed")
   ps=p.stat()
   if (ps.st_uid,ps.st_gid,stat.S_IMODE(ps.st_mode),ps.st_nlink)!=(uid,gid,mode,1): raise CoreRuntimeError("owned service file metadata changed")
   if p==UNIT and guarded_old:
    if _projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)!=_unit(
        adapter_source=old_scope.old_source,cohort_gate=True,
        backup_generation=old_scope.old_adapter_generation):
     raise CoreRuntimeError("physical guarded old unit differs")
   elif not (d["state"]=="retiring" and d.get("cleanup_allow_partial")) and _digest(p)!=d.get(k):
    raise CoreRuntimeError("owned service file changed")
  if d.get("adapter_migration_state") == "preparing":
   raise CoreRuntimeError("adapter source migration recovery is required")
  if d.get("adapter_update_state") in {"preparing", "starting"} and not guarded_new:
   raise CoreRuntimeError("adapter source update recovery is required")
  if d.get("adapter_migration_state") == "active":
   adapter_source=d.get("adapter_source")
   if (not isinstance(adapter_source,str)
       or not re.fullmatch(r"[0-9a-f]{64}",str(d.get("adapter_generation","")))
       or not re.fullmatch(r"[0-9a-f]{64}",str(d.get("core_source_generation","")))
       or not re.fullmatch(r"[0-9a-f]{64}",str(d.get("plugin_selection_sha256","")))):
    raise CoreRuntimeError("adapter migration custody record is incomplete")
   _validate_adapter_generation_path(Path(adapter_source))
   if d.get("adapter_update_state")=="active":
    _validate_adapter_update_history(d)
   unit_bytes=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
   if b"LoadCredential=adapter-update-cohort:" in unit_bytes:
    if guarded_old:
     pass
    elif guarded_new:
     _validate_guarded_new_read(new_scope)
    else:
     _validate_adapter_update_cohort_journal(d,raw_journal)
  else:
   adapter_source=None
  expected_units={hashlib.sha256(_unit(adapter_source=adapter_source)).hexdigest(),
      hashlib.sha256(_unit(startup_guard=False,adapter_source=adapter_source)).hexdigest()}
  if d.get("adapter_migration_state")=="active" and d.get("adapter_update_cohort_transaction_id") and not guarded_old:
   expected_units.add(hashlib.sha256(_unit(adapter_source=adapter_source,cohort_gate=True,
    backup_generation=_journal_adapter_backup_generation(d))).hexdigest())
  if d["state"]!="retiring" and not guarded_old and (d["unit_sha256"] not in expected_units or
      hashlib.sha256(_launcher(adapter_source=adapter_source)).hexdigest()!=d["launcher_sha256"]):
   raise CoreRuntimeError("owned service recipe differs from the reviewed source")
 return d
def status():
 try: d=_journal()
 except CoreRuntimeError as e: return "pending: "+str(e)
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 if active!="active" or not _owned_listener():
  return f"pending: owned unit is {active or 'unknown'} or its process-bound loopback listener is unproven"
 return f"owned isolated service and process-bound loopback listener verified at 127.0.0.1:8766; authenticated chat and restart proof pending; source {d['source_commit']}"

def _owned_listener(*,adapter_source=ADAPTER_SOURCE,legacy_launcher=False):
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
  expected_path=str(SOURCE if legacy_launcher else Path(f"{SOURCE}:{adapter_source}")).encode("ascii")
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

def _owned_listener_pidfd(*,adapter_source=ADAPTER_SOURCE):
 """Recheck one live systemd PID and its listener through a stable PIDFD."""
 pidfd=None
 try:
  if not hasattr(os,"pidfd_open"): return False
  pid_text=_run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()
  pid=int(pid_text)
  if pid<=1: return False
  pidfd=os.pidfd_open(pid,0)
  poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
  if (poller.poll(0) or not _owned_listener(adapter_source=adapter_source)
      or _run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()!=str(pid)
      or poller.poll(0)):
   return False
  return True
 except (OSError,ValueError,CoreRuntimeError):
  return False
 finally:
  if pidfd is not None: os.close(pidfd)

def _adapter_process_identity(adapter_source,adapter_generation,core_generation,pid):
 """Hash current kernel/systemd process identity; content is private recovery data."""
 proc=Path("/proc")/str(pid)
 info=proc.stat()
 if info.st_uid!=1000: raise CoreRuntimeError("captured adapter process owner differs")
 stat_text=(proc/"stat").read_text(); close=stat_text.rfind(")")
 fields=stat_text[close+1:].split() if close>=0 else []
 if len(fields)<20: raise CoreRuntimeError("captured adapter process start identity is unavailable")
 start_ticks=fields[19]
 boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
 cgroup=(proc/"cgroup").read_bytes()
 argv=(proc/"cmdline").read_bytes()
 invocation=_run(["systemctl","show","--property=InvocationID","--value",SERVICE],False).stdout.strip()
 if re.fullmatch(r"[0-9a-f]{32}",invocation or "") is None:
  raise CoreRuntimeError("captured service invocation identity is unavailable")
 evidence={"boot_id":boot_id,"pid":pid,"start_ticks":start_ticks,
  "adapter_source":str(adapter_source),"adapter_generation":adapter_generation,
  "core_source_generation":core_generation,"invocation_id":invocation,
  "cgroup_sha256":hashlib.sha256(cgroup).hexdigest(),
  "argv_sha256":hashlib.sha256(argv).hexdigest()}
 if not _owned_listener(adapter_source=adapter_source):
  raise CoreRuntimeError("captured adapter process does not own the verified listener")
 return evidence,hashlib.sha256(_canonical_json(evidence)).hexdigest()

def _issue_guarded_old_read(*,cohort,cohort_raw,record,journal_raw,old_unit,
                            old_launcher,pidfd,pid,process_identity_sha256,
                            purpose="resources-readback"):
 if (os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
     or purpose not in {"resources-readback","primary-rebase-readback"}
     or cohort.get("phase") not in {"prepared","resources-rebound"}
     or hashlib.sha256(journal_raw).hexdigest()!=cohort.get("old_journal_sha256")
     or hashlib.sha256(old_unit).hexdigest()!=cohort.get("old_unit_sha256")
     or hashlib.sha256(old_launcher).hexdigest()!=cohort.get("old_launcher_sha256")
     or hashlib.sha256(_unit(adapter_source=cohort["old_source"],cohort_gate=True,
       backup_generation=cohort["old_adapter_generation"])).hexdigest()
        !=cohort.get("guarded_old_unit_sha256")
     or hashlib.sha256(old_launcher).hexdigest()!=record.get("launcher_sha256")
     or record.get("adapter_source")!=cohort.get("old_source")
     or record.get("adapter_generation")!=cohort.get("old_adapter_generation")
     or record.get("core_source_generation")!=cohort.get("old_core_source_generation")
     or not _owned_listener_pidfd(adapter_source=Path(cohort["old_source"]))):
  raise CoreRuntimeError("exact guarded old-read custody cannot be issued")
 evidence,actual_identity=_adapter_process_identity(
  Path(cohort["old_source"]),cohort["old_adapter_generation"],
  cohort["old_core_source_generation"],pid)
 poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 if (actual_identity!=process_identity_sha256
     or actual_identity!=cohort.get("old_process_identity_sha256")
     or poller.poll(0)):
  raise CoreRuntimeError("captured old adapter process changed before guarded read")
 value=GuardedOldReadCustody(purpose,cohort["cohort_transaction_id"],
  hashlib.sha256(cohort_raw).hexdigest(),cohort["phase"],ROOT_UID,
  "jarvis-primary-home",cohort["old_journal_sha256"],cohort["old_source"],
  cohort["old_adapter_generation"],cohort["old_core_source_generation"],
  cohort["old_unit_sha256"],cohort["old_launcher_sha256"],
  cohort["old_source_recipe_sha256"],cohort["guarded_old_unit_sha256"],
  cohort["guarded_old_recipe_sha256"],cohort["old_process_identity_sha256"],
  pid,evidence["start_ticks"],evidence["boot_id"],time.monotonic()+360.0,
  pidfd,_GUARDED_OLD_READ_SEAL)
 _GUARDED_OLD_READ_ACTIVE[id(value)]=value
 return value

def _validate_guarded_old_read(value):
 try:
  if (type(value) is not GuardedOldReadCustody
      or value._seal is not _GUARDED_OLD_READ_SEAL
      or _GUARDED_OLD_READ_ACTIVE.get(id(value)) is not value
      or os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
      or value.owner_uid!=ROOT_UID or value.home_role!="jarvis-primary-home"
      or value.purpose not in {"resources-readback","primary-rebase-readback"}
      or time.monotonic()>=value.expires_monotonic):
   return False
  cohort,raw=_read_adapter_update_cohort()
  journal_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
  unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
  launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
  row=json.loads(journal_raw)
  evidence,identity=_adapter_process_identity(Path(value.old_source),
   value.old_adapter_generation,value.old_core_source_generation,value.pid)
  poller=select.poll(); poller.register(value.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
  return bool(cohort["phase"] in {"prepared","resources-rebound"}
   and cohort["phase"]==value.phase
   and cohort["cohort_transaction_id"]==value.cohort_transaction_id
   and hashlib.sha256(raw).hexdigest()==value.cohort_sha256
   and hashlib.sha256(journal_raw).hexdigest()==value.old_journal_sha256
   and row.get("adapter_source")==value.old_source
   and row.get("adapter_generation")==value.old_adapter_generation
   and row.get("core_source_generation")==value.old_core_source_generation
   and unit==_unit(adapter_source=value.old_source,cohort_gate=True,
      backup_generation=value.old_adapter_generation)
   and hashlib.sha256(unit).hexdigest()==value.guarded_old_unit_sha256
   and hashlib.sha256(launcher).hexdigest()==value.old_launcher_sha256
   and _adapter_recipe_sha256(value.old_source,value.old_adapter_generation,
       value.guarded_old_unit_sha256,value.old_launcher_sha256)==value.guarded_old_recipe_sha256
   and cohort.get("old_process_identity_sha256")==identity==value.old_process_identity_sha256
   and evidence["start_ticks"]==value.start_ticks and evidence["boot_id"]==value.boot_id
   and not poller.poll(0)
   and _owned_listener_pidfd(adapter_source=Path(value.old_source)))
 except Exception:
  return False

@contextmanager
def _guarded_old_read_scope(value,*,purpose):
 if purpose not in {"resources-readback","primary-rebase-readback"} or not _validate_guarded_old_read(value):
  raise CoreRuntimeError("guarded old-source read scope is stale")
 token=_GUARDED_OLD_READ_CONTEXT.set(value)
 try:
  yield
 finally:
  _GUARDED_OLD_READ_CONTEXT.reset(token)

def _issue_guarded_new_read(*,cohort,cohort_raw,record,journal_raw,resources_raw,unit,
                            launcher,pidfd,pid,process_identity_sha256,purpose):
 if (os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
     or purpose not in {"resources-readback","primary-rebase-readback","primary-initial-adoption"}
     or cohort.get("phase") not in {"source-starting","bindings-verified"}
     or hashlib.sha256(journal_raw).hexdigest()!=cohort.get("starting_journal_sha256")
     or hashlib.sha256(resources_raw).hexdigest()!=cohort.get("starting_resources_record_sha256")
     or hashlib.sha256(unit).hexdigest()!=cohort.get("new_unit_sha256")
     or hashlib.sha256(launcher).hexdigest()!=cohort.get("new_launcher_sha256")
     or record.get("adapter_source")!=cohort.get("new_source")
     or record.get("adapter_generation")!=cohort.get("new_adapter_generation")
     or record.get("core_source_generation")!=cohort.get("new_core_source_generation")
     or not _owned_listener_pidfd(adapter_source=Path(cohort["new_source"]))):
  raise CoreRuntimeError("exact guarded new-read custody cannot be issued")
 evidence,identity=_adapter_process_identity(Path(cohort["new_source"]),
  cohort["new_adapter_generation"],cohort["new_core_source_generation"],pid)
 poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 if identity!=process_identity_sha256 or poller.poll(0):
  raise CoreRuntimeError("new adapter process changed before guarded read")
 value=GuardedNewReadCustody(purpose,cohort["cohort_transaction_id"],
  hashlib.sha256(cohort_raw).hexdigest(),cohort["phase"],ROOT_UID,
  "jarvis-primary-home",cohort["starting_journal_sha256"],
  cohort["starting_resources_record_sha256"],cohort["new_source"],
  cohort["new_adapter_generation"],cohort["new_core_source_generation"],
  cohort["new_unit_sha256"],cohort["new_launcher_sha256"],
  cohort["new_source_recipe_sha256"],identity,pid,evidence["start_ticks"],
  evidence["boot_id"],time.monotonic()+360.0,pidfd,_GUARDED_NEW_READ_SEAL)
 _GUARDED_NEW_READ_ACTIVE[id(value)]=value
 return value

def _validate_guarded_new_read(value):
 try:
  if (type(value) is not GuardedNewReadCustody
      or value._seal is not _GUARDED_NEW_READ_SEAL
      or _GUARDED_NEW_READ_ACTIVE.get(id(value)) is not value
      or os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
      or value.owner_uid!=ROOT_UID or value.home_role!="jarvis-primary-home"
      or value.purpose not in {"resources-readback","primary-rebase-readback","primary-initial-adoption"}
      or time.monotonic()>=value.expires_monotonic):
   return False
  cohort,raw=_read_adapter_update_cohort()
  journal_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
  resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
  unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
  launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
  record=json.loads(journal_raw)
  evidence,identity=_adapter_process_identity(Path(value.new_source),
   value.new_adapter_generation,value.new_core_source_generation,value.pid)
  poller=select.poll(); poller.register(value.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
  initial=cohort.get("initial_primary_transition")
  initial_state=initial.get("state") if type(initial) is dict else None
  purpose_allowed=(
   (value.purpose=="primary-initial-adoption" and cohort["phase"]=="source-starting"
    and initial_state in {"preparing","writing","adopted","rolling-back"})
   or (value.purpose in {"resources-readback","primary-rebase-readback"}
    and initial_state not in {"preparing","writing","rolling-back"}))
  primary_stage_allowed=True
  if value.purpose=="primary-initial-adoption":
   if initial_state in {"pending","preparing"} and initial.get("preparing_record_sha256") is None:
    try:
     os.stat(PRIMARY_PROMPT_JOURNAL,follow_symlinks=False)
     primary_stage_allowed=False
    except FileNotFoundError:
     primary_stage_allowed=True
   else:
    try:
     primary_raw=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
      mode=0o600,maximum=64*1024)
     primary_row=json.loads(primary_raw)
     expected_stage={"preparing":"preparing","writing":"writing","adopted":"adopted",
                     "rolling-back":{"rolling_back","rolled_back"}}[initial_state]
     primary_stage_allowed=(primary_row.get("state") in expected_stage
        if type(expected_stage) is set else primary_row.get("state")==expected_stage)
    except Exception:
     primary_stage_allowed=False
  return bool(purpose_allowed and primary_stage_allowed
   and cohort["phase"] in {"source-starting","bindings-verified"}
   and cohort["phase"]==value.phase and cohort["cohort_transaction_id"]==value.cohort_transaction_id
   and hashlib.sha256(raw).hexdigest()==value.cohort_sha256
   and hashlib.sha256(journal_raw).hexdigest()==value.starting_journal_sha256
   and hashlib.sha256(resources_raw).hexdigest()==value.starting_resources_record_sha256
   and hashlib.sha256(unit).hexdigest()==value.new_unit_sha256
   and hashlib.sha256(launcher).hexdigest()==value.new_launcher_sha256
   and record.get("adapter_source")==value.new_source
   and record.get("adapter_generation")==value.new_adapter_generation
   and record.get("core_source_generation")==value.new_core_source_generation
   and record.get("adapter_update_state")=="starting"
   and _adapter_recipe_sha256(value.new_source,value.new_adapter_generation,
     value.new_unit_sha256,value.new_launcher_sha256)==value.new_source_recipe_sha256
   and identity==value.process_identity_sha256
   and evidence["start_ticks"]==value.start_ticks and evidence["boot_id"]==value.boot_id
   and not poller.poll(0) and _owned_listener_pidfd(adapter_source=Path(value.new_source)))
 except Exception:
  return False

@contextmanager
def _guarded_new_read_scope(value,*,purpose):
 if (purpose!=value.purpose or not _validate_guarded_new_read(value)):
  raise CoreRuntimeError("guarded new-source read scope is stale")
 token=_GUARDED_NEW_READ_CONTEXT.set(value)
 try:
  yield
 finally:
  _GUARDED_NEW_READ_CONTEXT.reset(token)

def _initial_primary_transition_row(cohort):
 row=cohort.get("initial_primary_transition") if type(cohort) is dict else None
 if type(row) is not dict or set(row)!=_INITIAL_PRIMARY_TRANSITION_FIELDS:
  raise CoreRuntimeError("initial primary cohort row is unavailable")
 return row

def _initial_primary_current(custody,*,allow_unrecorded_stage=False):
 """Recheck exact current cohort/process/owner bytes for the fixed manager seam."""
 try:
  if (type(custody) is not InitialPrimaryAdoptionCustody
      or custody._seal is not _INITIAL_PRIMARY_ADOPTION_SEAL
      or os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
      or time.monotonic()>=custody.expires_monotonic
      or time.monotonic()>=custody.deadline_monotonic):
   return False
  held=_INITIAL_PRIMARY_ADOPTION_ACTIVE.get(id(custody))
  if type(held) is not dict or held.get("object") is not custody:
   return False
  cohort,cohort_raw=_read_adapter_update_cohort()
  transition=_initial_primary_transition_row(cohort)
  if (cohort.get("cohort_transaction_id")!=custody.transaction_id
      or cohort.get("phase")!="source-starting"
      or hashlib.sha256(cohort_raw).hexdigest()!=held.get("current_cohort_sha256")
      or cohort.get("new_source")!=custody.source
      or cohort.get("old_adapter_generation")!=custody.old_adapter_generation
      or cohort.get("new_adapter_generation")!=custody.new_adapter_generation
      or cohort.get("new_core_source_generation")!=custody.core_source_generation
      or cohort.get("new_artifact_sha256")!=custody.artifact_a1_sha256
      or cohort.get("starting_journal_sha256")!=custody.starting_journal_sha256
      or cohort.get("starting_resources_record_sha256")!=held.get("current_resources_sha256")
      or cohort.get("initial_primary_transition")!=held.get("transition_row")
      or transition.get("prior_record_state")!="absent"
      or cohort.get("primary_record_sha256") not in {_ABSENT_DIGEST,
          transition.get("preparing_record_sha256"),transition.get("writing_record_sha256"),
          transition.get("adopted_record_sha256")}):
   return False
  journal_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
  resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
  unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
  launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
  record=json.loads(journal_raw)
  if (hashlib.sha256(journal_raw).hexdigest()!=custody.starting_journal_sha256
      or hashlib.sha256(resources_raw).hexdigest()!=held.get("current_resources_sha256")
      or hashlib.sha256(unit).hexdigest()!=custody.unit_sha256
      or hashlib.sha256(launcher).hexdigest()!=custody.launcher_sha256
      or record.get("adapter_update_state")!="starting"
      or record.get("adapter_update_cohort_transaction_id")!=custody.transaction_id
      or record.get("adapter_source")!=custody.source
      or record.get("adapter_generation")!=custody.new_adapter_generation
      or record.get("core_source_generation")!=custody.core_source_generation
      or _core_source_generation()!=custody.core_source_generation):
   return False
  from .remote.core_gateway_inspector import _current_native_adapter_generation
  if _current_native_adapter_generation(deadline=time.monotonic()+35.0)!=custody.new_adapter_generation:
   return False
  evidence,identity=_adapter_process_identity(Path(custody.source),
   custody.new_adapter_generation,custody.core_source_generation,custody.peer_pid)
  poller=select.poll(); poller.register(custody.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
  if (identity!=custody.process_identity_sha256 or evidence.get("start_ticks")!=custody.peer_start_ticks
      or evidence.get("boot_id")!=custody.boot_id
      or evidence.get("invocation_id")!=custody.invocation_id or poller.poll(0)
      or not _owned_listener_pidfd(adapter_source=Path(custody.source))):
   return False
  from . import primary_prompt_manager as primary
  try:
   primary_raw=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
    mode=0o600,maximum=64*1024)
   primary_row=json.loads(primary_raw)
  except FileNotFoundError:
   primary_raw=None; primary_row=None
  state=transition["state"]
  if state in {"pending","preparing"} and primary_raw is None:
   soul,signature=primary._read_soul(sys.modules[__name__])
   if (hashlib.sha256(soul).hexdigest()!=transition["prior_soul_sha256"]
       or tuple(signature)!=tuple(transition["prior_soul_signature"])): return False
  elif state=="pending":
   if primary_raw is not None:
    if not (allow_unrecorded_stage and type(primary_row) is dict
        and primary_row.get("state")=="preparing"):
     return False
   soul,signature=primary._read_soul(sys.modules[__name__])
   if (hashlib.sha256(soul).hexdigest()!=transition["prior_soul_sha256"]
       or tuple(signature)!=tuple(transition["prior_soul_signature"])
       or primary_row.get("prior_soul_sha256")!=transition["prior_soul_sha256"]
       or primary_row.get("artifact_sha256")!=custody.artifact_a1_sha256
       or primary_row.get("core_source_generation")!=custody.core_source_generation):
     if not allow_unrecorded_stage: return False
  else:
   if type(primary_row) is not dict: return False
   expected_digest=transition.get({"preparing":"preparing_record_sha256",
    "writing":"writing_record_sha256","adopted":"adopted_record_sha256",
    "rolling-back":"preparing_record_sha256"}.get(state,""))
   current_stage=primary_row.get("state")
   next_stage={"preparing":"writing","writing":"adopted"}.get(state)
   digest_matches=expected_digest is not None and hashlib.sha256(primary_raw).hexdigest()==expected_digest
   armed_prepare=(allow_unrecorded_stage and state=="preparing"
      and transition.get("preparing_record_sha256") is None and current_stage=="preparing")
   if not digest_matches and not armed_prepare and not (allow_unrecorded_stage and current_stage==next_stage): return False
   soul,signature=primary._read_soul(sys.modules[__name__])
   if primary_row.get("prior_soul_sha256")!=transition["prior_soul_sha256"]:
    return False
   if state in {"preparing","writing"} and hashlib.sha256(soul).hexdigest() not in {
       transition["prior_soul_sha256"],transition["desired_soul_sha256"]}: return False
   effective_state=current_stage if allow_unrecorded_stage and current_stage==next_stage else state
   if effective_state=="adopted" and hashlib.sha256(soul).hexdigest()!=transition["desired_soul_sha256"]: return False
   if effective_state=="adopted" and (primary_row.get("result_soul_sha256")!=transition["desired_soul_sha256"]
       or tuple(signature)!=tuple(primary_row.get("result_soul_signature",()))
       or transition.get("after_resources_record_sha256") is None): return False
   backup=primary._backup_read(sys.modules[__name__],primary_row)
   backup_sha=hashlib.sha256(backup).hexdigest()
   if (backup_sha!=transition.get("owner_backup_sha256")
       and not (allow_unrecorded_stage and state=="preparing"
          and transition.get("owner_backup_sha256") is None
          and backup_sha==transition.get("prior_soul_sha256"))): return False
  return True
 except Exception:
  return False

def verify_initial_primary_adoption_custody(custody):
 if not _initial_primary_current(custody,allow_unrecorded_stage=True):
  raise CoreRuntimeError("initial primary adoption custody is stale or foreign")
 return True

def _initial_primary_recovery_snapshot_sha256(prior,contents):
 """Hash the exact protected rollback snapshot without copying its contents."""
 names=("journal.json","resources-record.json","overlay-record.json",
  "primary-record.json","obsidian-registration.json","unit","launcher","cohort.json")
 rows={"prior":hashlib.sha256(_canonical_json(prior)).hexdigest()}
 for name in names:
  value=contents.get(name)
  if value is not None and type(value) is not bytes: return None
  rows[name]=hashlib.sha256(value or b"").hexdigest()
 return hashlib.sha256(_canonical_json(rows)).hexdigest()

def _restored_soul_signature_matches(signature,prior_signature):
 """Match stable ownership metadata after atomic replacement, not old inode/time."""
 return bool(type(signature) in {tuple,list} and type(prior_signature) in {tuple,list}
  and len(signature)==len(prior_signature)==9
  and all(type(part) is int and part>=0 for part in signature)
  and all(type(part) is int and part>=0 for part in prior_signature)
  and stat.S_ISREG(signature[2]) and signature[5]==1
  and signature[3]==prior_signature[3] and signature[4]==prior_signature[4]
  and stat.S_IMODE(signature[2])==stat.S_IMODE(prior_signature[2])
  and signature[6]==prior_signature[6])

def _initial_primary_rollback_current(custody):
 """Verify offline recovery authority while the owned service remains stopped."""
 try:
  held=_INITIAL_PRIMARY_ROLLBACK_ACTIVE.get(id(custody))
  if (type(custody) is not InitialPrimaryRollbackCustody
      or custody._seal is not _INITIAL_PRIMARY_ROLLBACK_SEAL
      or held is None or held.get("object") is not custody
      or os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
      or custody.schema!=1 or custody.purpose!="initial-primary-offline-rollback"
      or custody.owner_uid!=1000 or custody.home_role!="jarvis-primary-home"
      or time.monotonic()>=custody.expires_monotonic):
   return False
  reference=held.get("reference")
  prior,contents=_read_adapter_update_backup(reference)
  if _initial_primary_recovery_snapshot_sha256(prior,contents)!=custody.recovery_snapshot_sha256:
   return False
  cohort,cohort_raw=_read_adapter_update_cohort()
  transition=_initial_primary_transition_row(cohort)
  journal=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
  resources=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
  unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
  launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
  if (hashlib.sha256(cohort_raw).hexdigest()!=custody.cohort_sha256
      or cohort.get("phase")!="rolling-back"
      or hashlib.sha256(_canonical_json(transition)).hexdigest()!=custody.initial_transition_sha256
      or transition.get("state")!="rolling-back"
      or hashlib.sha256(journal).hexdigest()!=custody.journal_sha256
      or hashlib.sha256(resources).hexdigest()!=custody.resources_record_sha256
      or hashlib.sha256(unit).hexdigest()!=custody.unit_sha256
      or hashlib.sha256(launcher).hexdigest()!=custody.launcher_sha256
      or cohort.get("cohort_transaction_id")!=custody.transaction_id
      or cohort.get("new_source")!=custody.source
      or cohort.get("new_adapter_generation")!=custody.adapter_generation
      or cohort.get("new_core_source_generation")!=custody.core_source_generation
      or cohort.get("new_source_recipe_sha256")!=custody.source_recipe_sha256
      or cohort.get("new_artifact_sha256")!=custody.artifact_a1_sha256
      or transition.get("owner_backup_sha256")!=custody.owner_backup_sha256):
   return False
  old_source=Path(prior["adapter_source"])
  expected_guarded=_unit(adapter_source=old_source,cohort_gate=True,
   backup_generation=cohort["old_adapter_generation"])
  if (unit!=expected_guarded or launcher not in {
      contents["launcher"],_launcher(adapter_source=Path(cohort["new_source"]))}):
   return False
  active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
  main_pid=_run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip()
  if active=="active" or main_pid not in {"","0"}:
   return False
  if any(_owned_listener(adapter_source=Path(source)) for source in
      {cohort["old_source"],cohort["new_source"]}): return False
  if _core_source_generation()!=custody.core_source_generation:
   return False
  from .remote.core_gateway_inspector import _current_native_adapter_generation
  if _current_native_adapter_generation(deadline=time.monotonic()+35.0)!=custody.adapter_generation:
   return False
  from .registry import manual_jarvis_skills as native
  generation=HERMES_HOME/"skills"/native._GENERATION
  archive=_projection_file(RESOURCES_CAS/(custody.artifact_a1_sha256+".zip"),
   owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
  manifest,files,_helper=native._read_transition_archive(archive,custody.artifact_a1_sha256)
  installed_raw=_projection_file(generation/native._OWNER_FILE,owner=1000,group=1000,
   mode=0o600,maximum=2*1024*1024)
  tree_sha=_hash_generation_tree(HERMES_HOME,manifest,files,custody.artifact_a1_sha256)
  if (hashlib.sha256(installed_raw).hexdigest()!=custody.installed_journal_sha256
      or tree_sha!=custody.installed_tree_sha256): return False
  primary_raw=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
   mode=0o600,maximum=64*1024)
  if hashlib.sha256(primary_raw).hexdigest()!=custody.primary_stage_sha256:
   return False
  from . import primary_prompt_manager as primary
  row=json.loads(primary_raw); soul,signature=primary._read_soul(sys.modules[__name__])
  if (row.get("state") not in {"preparing","writing","adopted"}
      or row.get("prior_soul_sha256")!=custody.prior_soul_sha256
      or row.get("source_prompt_sha256")!=custody.source_prompt_sha256
      or row.get("managed_block_sha256")!=custody.managed_block_sha256
      or row.get("owner_backup_name")!=custody.owner_backup_sha256
      or hashlib.sha256(soul).hexdigest() not in {
       custody.prior_soul_sha256,custody.desired_soul_sha256}
      or (hashlib.sha256(soul).hexdigest()==custody.prior_soul_sha256
          and not _restored_soul_signature_matches(signature,custody.prior_soul_signature))):
   return False
  backup=primary._backup_read(sys.modules[__name__],row)
  return hashlib.sha256(backup).hexdigest()==custody.owner_backup_sha256
 except Exception:
  return False

def verify_initial_primary_rollback_custody(custody):
 if not _initial_primary_rollback_current(custody):
  raise CoreRuntimeError("initial primary offline rollback custody is stale or foreign")
 return True

def _issue_initial_primary_rollback_custody(*,reference,prior,contents,cohort,cohort_raw):
 """Issue a fresh offline recovery capability only after the fixed service is stopped."""
 if os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get():
  raise CoreRuntimeError("initial primary offline rollback requires the Root updater lock")
 transition=_initial_primary_transition_row(cohort)
 if cohort.get("phase")!="rolling-back" or transition.get("state")!="rolling-back":
  raise CoreRuntimeError("initial primary rollback is not the exact rolling-back cohort")
 # A crash can occur after the manager's atomic stage write and before its
 # Root stage recorder updates C. Reconcile only the single exact next stage;
 # never turn an arbitrary manager row into rollback evidence.
 primary_raw=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
  mode=0o600,maximum=64*1024)
 from . import primary_prompt_manager as primary
 stage_row=json.loads(primary_raw); stage=stage_row.get("state")
 backup=primary._backup_read(sys.modules[__name__],stage_row)
 backup_sha=hashlib.sha256(backup).hexdigest()
 if (backup_sha!=transition.get("prior_soul_sha256")
     or stage_row.get("owner_backup_name")!=backup_sha):
  raise CoreRuntimeError("initial primary rollback stage lost its exact immutable prior backup")
 stage_digest=hashlib.sha256(primary_raw).hexdigest()
 staged=dict(transition)
 if staged.get("owner_backup_sha256") is None: staged["owner_backup_sha256"]=backup_sha
 if stage=="preparing" and staged.get("preparing_record_sha256") is None:
  staged["preparing_record_sha256"]=stage_digest
 elif stage=="writing" and staged.get("writing_record_sha256") is None:
  if staged.get("preparing_record_sha256") is None:
   raise CoreRuntimeError("unrecorded initial writing stage has no retained preparing predecessor")
  staged["writing_record_sha256"]=stage_digest
 elif stage=="adopted" and staged.get("adopted_record_sha256") is None:
  if (staged.get("writing_record_sha256") is None
      or staged.get("after_resources_record_sha256")!=hashlib.sha256(
       _projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
        mode=0o600,maximum=16*1024)).hexdigest()):
   raise CoreRuntimeError("unrecorded initial adopted stage lacks its exact Resources predecessor")
  staged["adopted_record_sha256"]=stage_digest
 if staged!=transition:
  updated=dict(cohort); updated["initial_primary_transition"]=staged
  updated["primary_record_sha256"]=stage_digest
  cohort_raw=_write_adapter_update_cohort(updated,expected_raw=cohort_raw)
  cohort=updated; transition=staged
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 main_pid=_run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip()
 if active=="active" or main_pid not in {"","0"} or any(
     _owned_listener(adapter_source=Path(source)) for source in {cohort["old_source"],cohort["new_source"]}):
  raise CoreRuntimeError("initial primary rollback requires the owned service and listener stopped")
 row=json.loads(primary_raw); soul,signature=primary._read_soul(sys.modules[__name__])
 if (row.get("state") not in {"preparing","writing","adopted"}
     or row.get("prior_soul_sha256")!=transition.get("prior_soul_sha256")
     or row.get("source_prompt_sha256")!=transition.get("source_prompt_sha256")
     or row.get("managed_block_sha256")!=transition.get("managed_block_sha256")
     or hashlib.sha256(soul).hexdigest() not in {transition.get("prior_soul_sha256"),
      transition.get("desired_soul_sha256")}
     or (hashlib.sha256(soul).hexdigest()==transition.get("prior_soul_sha256")
      and not _restored_soul_signature_matches(
       signature,transition.get("prior_soul_signature",())))
     or backup_sha!=transition.get("owner_backup_sha256")
     or row.get("owner_backup_name")!=backup_sha):
  raise CoreRuntimeError("initial primary rollback evidence is not the exact owned stage")
 _retain_initial_primary_stage(cohort["cohort_transaction_id"],primary_raw)
 journal=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 resources=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
 unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
 launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
 expected_guarded=_unit(adapter_source=Path(prior["adapter_source"]),cohort_gate=True,
  backup_generation=cohort["old_adapter_generation"])
 if (unit!=expected_guarded or launcher not in {
     contents["launcher"],_launcher(adapter_source=Path(cohort["new_source"]))}):
  raise CoreRuntimeError("initial primary offline rollback recipes are not the exact guarded cohort files")
 from .registry import manual_jarvis_skills as native
 generation=HERMES_HOME/"skills"/native._GENERATION
 archive=_projection_file(RESOURCES_CAS/(cohort["new_artifact_sha256"]+".zip"),
  owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 manifest,files,_helper=native._read_transition_archive(
  archive,cohort["new_artifact_sha256"])
 _hash_generation_tree(HERMES_HOME,manifest,files,cohort["new_artifact_sha256"])
 installed_raw=_projection_file(generation/native._OWNER_FILE,owner=1000,group=1000,
  mode=0o600,maximum=2*1024*1024)
 values=dict(schema=1,purpose="initial-primary-offline-rollback",
  transaction_id=cohort["cohort_transaction_id"],cohort_sha256=hashlib.sha256(cohort_raw).hexdigest(),
  initial_transition_sha256=hashlib.sha256(_canonical_json(transition)).hexdigest(),
  recovery_snapshot_sha256=_initial_primary_recovery_snapshot_sha256(prior,contents),
  owner_uid=1000,home_role="jarvis-primary-home",source=cohort["new_source"],
  adapter_generation=cohort["new_adapter_generation"],
  core_source_generation=cohort["new_core_source_generation"],
  source_recipe_sha256=cohort["new_source_recipe_sha256"],
  unit_sha256=hashlib.sha256(unit).hexdigest(),launcher_sha256=hashlib.sha256(launcher).hexdigest(),
  journal_sha256=hashlib.sha256(journal).hexdigest(),
  resources_record_sha256=hashlib.sha256(resources).hexdigest(),
  artifact_a1_sha256=cohort["new_artifact_sha256"],
  installed_journal_sha256=hashlib.sha256(installed_raw).hexdigest(),
  installed_tree_sha256=_hash_generation_tree(HERMES_HOME,manifest,files,cohort["new_artifact_sha256"]),
  primary_stage_sha256=hashlib.sha256(primary_raw).hexdigest(),
  prior_soul_sha256=transition["prior_soul_sha256"],
  prior_soul_signature=tuple(transition["prior_soul_signature"]),
  desired_soul_sha256=transition["desired_soul_sha256"],
  source_prompt_sha256=transition["source_prompt_sha256"],
  managed_block_sha256=transition["managed_block_sha256"],
  owner_backup_sha256=backup_sha,owner_backup_name=row["owner_backup_name"],
  expires_monotonic=time.monotonic()+180.0,_seal=_INITIAL_PRIMARY_ROLLBACK_SEAL)
 custody=InitialPrimaryRollbackCustody(**values)
 _INITIAL_PRIMARY_ROLLBACK_ACTIVE[id(custody)]={"object":custody,"reference":reference}
 verify_initial_primary_rollback_custody(custody)
 return custody

def _issue_initial_primary_adoption_custody(*,cohort,cohort_raw,journal_raw,resources_raw,
    unit,launcher,pidfd,pid,process_identity_sha256,prior_soul,prior_signature,
    source_prompt,managed_block,desired_soul,owner_separator):
 """Seal the single initial append to the exact running source-starting tuple."""
 if (os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
     or type(cohort) is not dict or cohort.get("phase")!="source-starting"
     or type(prior_soul) is not bytes or type(source_prompt) is not bytes
     or type(managed_block) is not bytes or type(desired_soul) is not bytes
     or not isinstance(owner_separator,bytes)):
  raise CoreRuntimeError("initial primary adoption inputs are outside the fixed source cohort")
 transition=_initial_primary_transition_row(cohort)
 if (transition.get("state")!="preparing" or transition.get("prior_record_state")!="absent"
     or hashlib.sha256(cohort_raw).hexdigest()!=hashlib.sha256(
      _projection_file(ADAPTER_UPDATE_COHORT,owner=ROOT_UID,group=ROOT_UID,
       mode=0o400,maximum=128*1024)).hexdigest()
     or hashlib.sha256(journal_raw).hexdigest()!=cohort.get("starting_journal_sha256")
     or hashlib.sha256(resources_raw).hexdigest()!=cohort.get("starting_resources_record_sha256")
     or hashlib.sha256(unit).hexdigest()!=cohort.get("new_unit_sha256")
     or hashlib.sha256(launcher).hexdigest()!=cohort.get("new_launcher_sha256")
     or hashlib.sha256(prior_soul).hexdigest()!=transition.get("prior_soul_sha256")
     or tuple(prior_signature)!=tuple(transition.get("prior_soul_signature",()))
     or hashlib.sha256(source_prompt).hexdigest()!=transition.get("source_prompt_sha256")
     or hashlib.sha256(managed_block).hexdigest()!=transition.get("managed_block_sha256")
     or hashlib.sha256(desired_soul).hexdigest()!=transition.get("desired_soul_sha256")
     or owner_separator.hex()!=transition.get("owner_separator_hex")):
  raise CoreRuntimeError("initial primary adoption source or owner snapshot changed")
 record=json.loads(journal_raw)
 if (record.get("adapter_update_state")!="starting"
     or record.get("adapter_update_cohort_transaction_id")!=cohort.get("cohort_transaction_id")):
  raise CoreRuntimeError("initial primary adoption source journal is not current")
 evidence,identity=_adapter_process_identity(Path(cohort["new_source"]),
  cohort["new_adapter_generation"],cohort["new_core_source_generation"],pid)
 poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 if (identity!=process_identity_sha256 or poller.poll(0)
     or not _owned_listener_pidfd(adapter_source=Path(cohort["new_source"]))):
  raise CoreRuntimeError("initial primary adoption peer is not the held current listener")
 deadline=min(time.monotonic()+110.0,float(cohort.get("deadline_monotonic",time.monotonic()+110.0)))
 issued=time.monotonic()
 custody=InitialPrimaryAdoptionCustody(
  transaction_id=cohort["cohort_transaction_id"],cohort_sha256=hashlib.sha256(cohort_raw).hexdigest(),
  source=cohort["new_source"],old_adapter_generation=cohort["old_adapter_generation"],
  new_adapter_generation=cohort["new_adapter_generation"],
  core_source_generation=cohort["new_core_source_generation"],
  artifact_a1_sha256=cohort["new_artifact_sha256"],
  starting_journal_sha256=hashlib.sha256(journal_raw).hexdigest(),
  starting_resources_record_sha256=hashlib.sha256(resources_raw).hexdigest(),
  unit_sha256=hashlib.sha256(unit).hexdigest(),launcher_sha256=hashlib.sha256(launcher).hexdigest(),
  source_recipe_sha256=cohort["new_source_recipe_sha256"],
  process_identity_sha256=process_identity_sha256,
  prior_soul_sha256=hashlib.sha256(prior_soul).hexdigest(),
  prior_soul_signature=tuple(prior_signature),
  source_prompt_sha256=hashlib.sha256(source_prompt).hexdigest(),
  managed_block_sha256=hashlib.sha256(managed_block).hexdigest(),
  desired_soul_sha256=hashlib.sha256(desired_soul).hexdigest(),
  owner_separator_hex=owner_separator.hex(),peer_pid=pid,
  peer_start_ticks=evidence["start_ticks"],boot_id=evidence["boot_id"],
  invocation_id=evidence["invocation_id"],prior_record_sha256=_ABSENT_DIGEST,
  issued_monotonic=issued,deadline_monotonic=deadline,expires_monotonic=deadline,
  pidfd=pidfd,_seal=_INITIAL_PRIMARY_ADOPTION_SEAL)
 _INITIAL_PRIMARY_ADOPTION_ACTIVE[id(custody)]={
  "object":custody,"current_cohort_sha256":custody.cohort_sha256,
  "current_resources_sha256":custody.starting_resources_record_sha256,
  "transition_row":transition,"manager_record_raw":None,"manager_record_sha256":None,
 }
 return custody

def _arm_initial_primary_adoption(*,new_read,cohort,cohort_raw):
 """Close reboot admission before the primary manager's first durable write."""
 if (os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
     or not _validate_guarded_new_read(new_read)):
  raise CoreRuntimeError("initial primary preparation lost its current new-peer readback")
 transition=_initial_primary_transition_row(cohort)
 if transition.get("state")!="pending" or transition.get("prior_record_state")!="absent":
  raise CoreRuntimeError("initial primary lane is not genuinely pending")
 try:
  _projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
  raise CoreRuntimeError("primary ownership journal appeared before the authorized initial stage")
 except FileNotFoundError:
  pass
 from . import primary_prompt_manager as primary
 soul,signature=primary._read_soul(sys.modules[__name__])
 if (hashlib.sha256(soul).hexdigest()!=transition.get("prior_soul_sha256")
     or tuple(signature)!=tuple(transition.get("prior_soul_signature",()))):
  raise CoreRuntimeError("actual HOME SOUL changed before initial-primary preparation")
 updated=dict(cohort); next_transition=dict(transition); next_transition["state"]="preparing"
 updated["initial_primary_transition"]=next_transition
 recon=dict(updated["reconstruction"])
 recon["phase"]=updated["phase"]
 updated["reconstruction"]=recon
 updated["reconstruction_sha256"]=hashlib.sha256(_canonical_json(recon)).hexdigest()
 raw=_write_adapter_update_cohort(updated,expected_raw=cohort_raw)
 return updated,raw

def _initial_primary_record_and_soul():
 from . import primary_prompt_manager as primary
 try:
  raw=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
   mode=0o600,maximum=64*1024)
 except FileNotFoundError:
  return None,None,None,None
 record=primary._read_record(sys.modules[__name__])
 soul,signature=primary._read_soul(sys.modules[__name__])
 return raw,record,soul,tuple(signature)

def _retain_initial_primary_stage(transaction_id,raw):
 if (os.geteuid()!=ROOT_UID or re.fullmatch(r"[0-9a-f]{32}",str(transaction_id)) is None
     or type(raw) is not bytes or len(raw)>64*1024):
  raise CoreRuntimeError("initial primary stage cannot be retained")
 directory=ADAPTER_UPDATE_BACKUPS/("initial-primary-"+transaction_id)
 _ensure_dir(directory,ROOT_UID,ROOT_UID,0o700)
 digest=hashlib.sha256(raw).hexdigest(); path=directory/(digest+".json")
 if path.exists() or path.is_symlink():
  if _projection_file(path,owner=ROOT_UID,group=ROOT_UID,mode=0o400,maximum=64*1024)!=raw:
   raise CoreRuntimeError("retained initial primary stage digest collides with different bytes")
 else:
  _atomic(path,raw,0o400,ROOT_UID,ROOT_UID)
 return digest

def record_initial_primary_manager_stage(custody):
 """Record only the real fixed-manager journal state currently on disk."""
 if not _initial_primary_current(custody,allow_unrecorded_stage=True):
  raise CoreRuntimeError("initial primary manager stage is outside current Root custody")
 cohort,cohort_raw=_read_adapter_update_cohort()
 initial=_initial_primary_transition_row(cohort)
 raw,record,soul,signature=_initial_primary_record_and_soul()
 if type(record) is not dict or raw is None:
  raise CoreRuntimeError("fixed primary manager stage journal is missing")
 state=record.get("state"); previous=initial.get("state")
 transitions={"pending":{"preparing"},"preparing":{"preparing","writing","rolling_back"},
              "writing":{"adopted","rolling_back"},"adopted":{"rolling_back"},
              "rolling-back":{"rolling_back"}}
 mapped="rolling-back" if state in {"rolling_back","rolled_back"} else state
 if mapped not in transitions.get(previous,set()):
  raise CoreRuntimeError("primary manager journal stage transition is not the next exact state")
 if (record.get("core_source_generation")!=custody.core_source_generation
     or record.get("artifact_sha256")!=custody.artifact_a1_sha256
     or record.get("prior_soul_sha256")!=custody.prior_soul_sha256
     or record.get("source_prompt_sha256")!=custody.source_prompt_sha256
     or record.get("managed_block_sha256")!=custody.managed_block_sha256
     or record.get("owner_separator_hex")!=custody.owner_separator_hex):
  raise CoreRuntimeError("primary manager stage differs from the sealed initial-adoption inputs")
 backup=__import__("hermes_installer.primary_prompt_manager",fromlist=["_backup_read"])._backup_read(
  sys.modules[__name__],record)
 backup_sha=hashlib.sha256(backup).hexdigest()
 if backup_sha!=custody.prior_soul_sha256:
  raise CoreRuntimeError("initial primary immutable backup differs from the exact prior owner SOUL")
 if mapped in {"preparing","writing"} and hashlib.sha256(soul).hexdigest() not in {
     custody.prior_soul_sha256,custody.desired_soul_sha256}:
  raise CoreRuntimeError("initial primary manager stage found unrelated owner SOUL bytes")
 if mapped=="adopted" and (hashlib.sha256(soul).hexdigest()!=custody.desired_soul_sha256
     or record.get("result_soul_sha256")!=custody.desired_soul_sha256
     or tuple(signature)!=tuple(record.get("result_soul_signature",()))
     or initial.get("after_resources_record_sha256") is None):
  raise CoreRuntimeError("initial primary adopted journal lacks exact SOUL and Resources readback")
 updated=dict(cohort); transition=dict(initial); digest=hashlib.sha256(raw).hexdigest()
 transition["state"]=mapped; transition["owner_backup_sha256"]=backup_sha
 if mapped=="preparing": transition["preparing_record_sha256"]=digest
 elif mapped=="writing": transition["writing_record_sha256"]=digest
 elif mapped=="adopted": transition["adopted_record_sha256"]=digest
 updated["initial_primary_transition"]=transition
 updated["primary_record_sha256"]=digest
 new_raw=_write_adapter_update_cohort(updated,expected_raw=cohort_raw)
 held=_INITIAL_PRIMARY_ADOPTION_ACTIVE[id(custody)]
 held.update({"current_cohort_sha256":hashlib.sha256(new_raw).hexdigest(),
              "transition_row":transition,"manager_record_raw":raw,
              "manager_record_sha256":digest})
 _retain_initial_primary_stage(custody.transaction_id,raw)
 return True

@contextmanager
def initial_primary_adoption_scope(custody):
 verify_initial_primary_adoption_custody(custody)
 cohort,cohort_raw=_read_adapter_update_cohort()
 journal_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
 unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
 launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
 read=_issue_guarded_new_read(cohort=cohort,cohort_raw=cohort_raw,record=json.loads(journal_raw),
  journal_raw=journal_raw,resources_raw=resources_raw,unit=unit,launcher=launcher,
  pidfd=custody.pidfd,pid=custody.peer_pid,process_identity_sha256=custody.process_identity_sha256,
  purpose="primary-initial-adoption")
 new_token=_GUARDED_NEW_READ_CONTEXT.set(read)
 adoption_token=_INITIAL_PRIMARY_ADOPTION_CONTEXT.set(custody)
 try:
  verify_initial_primary_adoption_custody(custody)
  yield
 finally:
  _INITIAL_PRIMARY_ADOPTION_CONTEXT.reset(adoption_token)
  _GUARDED_NEW_READ_CONTEXT.reset(new_token)

def _initial_primary_writing_snapshot_matches(custody,cohort,transition,raw,record,soul,signature):
 """Join the exact durable writing row to fresh Root-read owner bytes."""
 digest=hashlib.sha256(raw).hexdigest() if type(raw) is bytes else None
 prior_signature=custody.prior_soul_signature
 valid_signature=(type(signature) in {list,tuple} and len(signature)==9
  and all(type(value) is int and value>=0 for value in signature)
  and type(prior_signature) is tuple and len(prior_signature)==9
  and all(type(value) is int and value>=0 for value in prior_signature)
  and stat.S_ISREG(signature[2]) and stat.S_ISREG(prior_signature[2])
  and stat.S_IMODE(signature[2])==stat.S_IMODE(prior_signature[2])
  and signature[3]==prior_signature[3] and signature[4]==prior_signature[4]
  and signature[5]==prior_signature[5]==1 and signature[6]==len(soul))
 return bool(
  type(record) is dict and transition.get("state")=="writing"
  and transition.get("after_resources_record_sha256") is None
  and record.get("state")=="writing"
  and digest==cohort.get("primary_record_sha256")
  and digest==transition.get("writing_record_sha256")
  and record.get("core_source_generation")==custody.core_source_generation
  and record.get("artifact_sha256")==custody.artifact_a1_sha256
  and record.get("prior_soul_sha256")==custody.prior_soul_sha256
  and record.get("source_prompt_sha256")==custody.source_prompt_sha256
  and record.get("managed_block_sha256")==custody.managed_block_sha256
  and record.get("owner_separator_hex")==custody.owner_separator_hex
  and record.get("result_soul_sha256")==custody.desired_soul_sha256
  and record.get("prior_soul_sha256")==transition.get("prior_soul_sha256")
  and record.get("source_prompt_sha256")==transition.get("source_prompt_sha256")
  and record.get("managed_block_sha256")==transition.get("managed_block_sha256")
  and record.get("owner_separator_hex")==transition.get("owner_separator_hex")
  and transition.get("desired_soul_sha256")==custody.desired_soul_sha256
  and record.get("result_soul_signature")==[]
  and valid_signature and type(soul) is bytes
  and hashlib.sha256(soul).hexdigest()==custody.desired_soul_sha256)

def refresh_initial_primary_starting_tuple(custody):
 """Refresh only the current starting Resources receipt after native adoption."""
 if not _initial_primary_current(custody):
  raise CoreRuntimeError("initial primary Resources refresh custody is stale")
 cohort,cohort_raw=_read_adapter_update_cohort()
 transition=_initial_primary_transition_row(cohort)
 if transition.get("state")!="writing" or transition.get("after_resources_record_sha256") is not None:
  raise CoreRuntimeError("initial primary Resources refresh is not the exact writing stage")
 primary_raw,primary_record,soul,signature=_initial_primary_record_and_soul()
 if not _initial_primary_writing_snapshot_matches(
     custody,cohort,transition,primary_raw,primary_record,soul,signature):
  raise CoreRuntimeError("initial primary write has not completed with exact owner bytes")
 with initial_primary_adoption_scope(custody):
  verify_initial_primary_adoption_custody(custody)
  archive,resources=_verified_resources_payload()
  # The native read may take time. Re-read the protected SOUL and manager row
  # after it so a concurrent replacement cannot be joined to this receipt.
  after_raw,after_record,after_soul,after_signature=_initial_primary_record_and_soul()
  if (not _initial_primary_writing_snapshot_matches(
       custody,cohort,transition,after_raw,after_record,after_soul,after_signature)
      or after_raw!=primary_raw or after_record!=primary_record
      or tuple(after_signature)!=tuple(signature)
      or not _initial_primary_current(custody)):
   raise CoreRuntimeError("initial primary write changed during native A1 readback")
 if (hashlib.sha256(archive).hexdigest()!=custody.artifact_a1_sha256
     or resources.get("artifact_sha256")!=custody.artifact_a1_sha256
     or resources.get("core_source_generation")!=custody.core_source_generation
     or resources.get("active_primary_prompt_sha256")!=custody.desired_soul_sha256
     or resources.get("loaded_skill_inventory_sha256") is None):
  raise CoreRuntimeError("native A1 Resources readback does not bind the adopted primary")
 journal_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 if hashlib.sha256(journal_raw).hexdigest()!=custody.starting_journal_sha256:
  raise CoreRuntimeError("Core journal changed before the initial-primary Resources refresh")
 record=_bind_resources_record_to_starting_journal(resources,journal_raw)
 resources_raw=(json.dumps(record,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
 updated=dict(cohort); next_transition=dict(transition)
 next_transition["after_resources_record_sha256"]=hashlib.sha256(resources_raw).hexdigest()
 updated["initial_primary_transition"]=next_transition
 updated["starting_resources_record_sha256"]=hashlib.sha256(resources_raw).hexdigest()
 recon=dict(updated["reconstruction"]); recon["new_discovery_sha256"]=hashlib.sha256(resources_raw).hexdigest()
 updated["reconstruction"]=recon
 updated["reconstruction_sha256"]=hashlib.sha256(_canonical_json(recon)).hexdigest()
 next_cohort_raw=_write_adapter_update_cohort(updated,expected_raw=cohort_raw)
 _write_resources_record_bytes(archive,record)
 if _projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
     mode=0o600,maximum=16*1024)!=resources_raw:
  raise CoreRuntimeError("initial-primary Resources receipt did not persist exactly")
 held=_INITIAL_PRIMARY_ADOPTION_ACTIVE[id(custody)]
 held.update({"current_cohort_sha256":hashlib.sha256(next_cohort_raw).hexdigest(),
  "current_resources_sha256":hashlib.sha256(resources_raw).hexdigest(),
  "transition_row":next_transition})
 return record

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
 if files[UNIT] not in {_unit(),_unit(cohort_gate=False)}:
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
 _atomic_replace(LAUNCHER,contents["launcher"],0o755,ROOT_UID,ROOT_UID)
 _atomic_replace(JOURNAL,contents["journal.json"],0o600,ROOT_UID,ROOT_UID)
 _atomic_replace(UNIT,contents["unit"],0o644,ROOT_UID,ROOT_UID)
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
  new_launcher,new_unit=_launcher(),_unit(cohort_gate=False)
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

def _validate_adapter_generation_path(path):
 """Validate a fixed root-owned immutable adapter generation path."""
 path=Path(path)
 if (not path.is_absolute() or path.parent.parent!=Path("/opt")
     or not re.fullmatch(r"hermes-installer-core-[0-9a-f]{9,64}",path.parent.name)):
  raise CoreRuntimeError("journaled installer adapter generation path is unsupported")
 fd=os.open("/",os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
 try:
  for component in path.parts[1:]:
   child=os.open(component,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)
                 |getattr(os,"O_NOFOLLOW",0),dir_fd=fd)
   info=os.fstat(child)
   if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=ROOT_UID
       or stat.S_IMODE(info.st_mode)&0o022):
    os.close(child); raise CoreRuntimeError("journaled adapter generation custody differs")
   os.close(fd); fd=child
 finally: os.close(fd)

def _read_active_adapter_runtime():
 """Read the complete active journaled cohort, including its process identity."""
 raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 try: record=json.loads(raw)
 except (ValueError,TypeError): raise CoreRuntimeError("core ownership journal invalid") from None
 if (type(record) is not dict or record.get("schema")!=1 or record.get("state") not in {"installed","active"}
     or record.get("service")!=SERVICE or record.get("adapter_migration_state")!="active"
     or not re.fullmatch(r"[0-9a-f]{64}",str(record.get("adapter_generation","")))
     or not re.fullmatch(r"[0-9a-f]{64}",str(record.get("core_source_generation","")))
     or not re.fullmatch(r"[0-9a-f]{64}",str(record.get("plugin_selection_sha256","")))):
  raise CoreRuntimeError("no complete journaled native adapter runtime is eligible for update")
 old_source=Path(record.get("adapter_source",""))
 _validate_adapter_generation_path(old_source)
 if record.get("adapter_update_state")=="active":
  _validate_adapter_update_history(record)
 identity=_identity()
 for key,source_key in (("source_commit","commit"),("lock_sha256","lock_sha256"),
                        ("python_sha256","python_sha256"),("python_link","python_link"),
                        ("python_uid","python_uid"),("python_gid","python_gid"),
                        ("python_mode","python_mode")):
  if record.get(key)!=identity.get(source_key):
   raise CoreRuntimeError("pinned Hermes core identity changed; adapter-only update is not eligible")
 if _core_source_generation()!=record["core_source_generation"]:
  raise CoreRuntimeError("current Hermes core source receipt differs from the journal")
 files={}
 for path,key,uid,gid,mode in FILE_CONTRACT:
  content=_projection_file(path,owner=uid,group=gid,mode=mode,maximum=256*1024)
  if record.get(key)!=hashlib.sha256(content).hexdigest():
   raise CoreRuntimeError("journal-owned core file or credential changed")
  files[path]=content
 allowed_units={_unit(adapter_source=old_source),
                _unit(startup_guard=False,adapter_source=old_source)}
 if record.get("adapter_update_cohort_transaction_id"):
  allowed_units.add(_unit(adapter_source=old_source,cohort_gate=True,
   backup_generation=_journal_adapter_backup_generation(record)))
 if files[UNIT] not in allowed_units or files[LAUNCHER]!=_launcher(adapter_source=old_source):
  raise CoreRuntimeError("journal-owned native core recipe differs")
 if b"LoadCredential=adapter-update-cohort:" in files[UNIT]:
  _validate_adapter_update_cohort_journal(record,raw)
 if not _owned_unit_loaded() or not _owned_listener_pidfd(adapter_source=old_source):
  raise CoreRuntimeError("journal-owned native core process or listener is not current")
 return record,raw,files

def _save_adapter_update_backup(record,raw_journal,files,selection_digest,
                                *,resources_record,overlay_record,primary_record,
                                obsidian_registration,prior_cohort,native_plugin_members=None):
 """Persist a root-only, immutable per-source recovery cohort before switching."""
 old_generation=record["adapter_generation"]
 _ensure_dir(ADAPTER_UPDATE_BACKUPS,ROOT_UID,ROOT_UID,0o700)
 backup=ADAPTER_UPDATE_BACKUPS/old_generation
 _ensure_dir(backup,ROOT_UID,ROOT_UID,0o700)
 prior_manifest_path=backup/"manifest.json"
 if native_plugin_members is not None and (prior_manifest_path.exists() or prior_manifest_path.is_symlink()):
  prior_manifest_raw=_projection_file(prior_manifest_path,owner=ROOT_UID,group=ROOT_UID,
   mode=0o600,maximum=4096)
  try: prior_manifest=json.loads(prior_manifest_raw)
  except (ValueError,TypeError): raise CoreRuntimeError("prior adapter backup manifest is malformed") from None
  if type(prior_manifest) is not dict or "native-plugin-plugin.yaml" not in prior_manifest:
   raise CoreRuntimeError("immutable prior adapter backup cannot be extended for native plugin transition")
 if native_plugin_members is None and (prior_manifest_path.exists() or prior_manifest_path.is_symlink()):
  prior_manifest_raw=_projection_file(prior_manifest_path,owner=ROOT_UID,group=ROOT_UID,
   mode=0o600,maximum=4096)
  try: prior_manifest=json.loads(prior_manifest_raw)
  except (ValueError,TypeError): raise CoreRuntimeError("prior adapter backup manifest is malformed") from None
  if type(prior_manifest) is not dict or any(name in prior_manifest for name in _NATIVE_PLUGIN_BACKUP_NAMES.values()):
   raise CoreRuntimeError("native plugin backup cannot be reinterpreted as a no-transition backup")
 if not re.fullmatch(r"[0-9a-f]{64}",str(selection_digest or "")):
  raise CoreRuntimeError("current native plugin selection receipt is unavailable")
 selection_json=(json.dumps({"schema":1,"selection_sha256":selection_digest},
                            sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
 names={"journal.json":raw_journal,"unit":files[UNIT],"launcher":files[LAUNCHER],
        "plugin-selection.json":selection_json,"resources-record.json":resources_record,
        "overlay-record.json":overlay_record,"primary-record.json":primary_record,
        "obsidian-registration.json":obsidian_registration,"cohort.json":prior_cohort}
 if native_plugin_members is not None:
  if type(native_plugin_members) not in (dict,MappingProxyType) or set(native_plugin_members)!=set(_NATIVE_PLUGIN_FILES):
   raise CoreRuntimeError("native plugin backup is not the fixed pair")
  for name,backup_name in _NATIVE_PLUGIN_BACKUP_NAMES.items():
   content=native_plugin_members[name]
   if type(content) is not bytes or not 1<=len(content)<=64*1024:
    raise CoreRuntimeError("native plugin backup member is not bounded bytes")
   names[backup_name]=content
 manifest={name:hashlib.sha256(content).hexdigest() for name,content in names.items()}
 manifest_bytes=(json.dumps(manifest,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
 allowed=set(names)|{"manifest.json"}
 if not set(os.listdir(backup))<=allowed:
  raise CoreRuntimeError("adapter update backup contains unowned entries")
 for name,content in names.items():
  path=backup/name
  if path.exists() or path.is_symlink():
   existing=_projection_file(path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
   if existing!=content: raise CoreRuntimeError("prior adapter update backup differs")
  else: _atomic(path,content,0o600,ROOT_UID,ROOT_UID)
 manifest_path=backup/"manifest.json"
 if manifest_path.exists() or manifest_path.is_symlink():
  if _projection_file(manifest_path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=4096)!=manifest_bytes:
   raise CoreRuntimeError("adapter update backup manifest differs")
 else: _atomic(manifest_path,manifest_bytes,0o600,ROOT_UID,ROOT_UID)
 return {"path":str(backup),"source_generation":old_generation,"files":manifest}

def _read_adapter_update_backup(reference):
 if (type(reference) is not dict or set(reference)!={"path","source_generation","files"}
     or not re.fullmatch(r"[0-9a-f]{64}",str(reference.get("source_generation","")))
     or reference.get("path")!=str(ADAPTER_UPDATE_BACKUPS/reference["source_generation"])):
  raise CoreRuntimeError("journaled adapter update backup reference is invalid")
 backup=Path(reference["path"]); info=backup.lstat()
 if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=ROOT_UID or info.st_gid!=ROOT_UID
     or stat.S_IMODE(info.st_mode)!=0o700
     or set(os.listdir(backup)) not in ({"journal.json","unit","launcher","plugin-selection.json",
       "resources-record.json","overlay-record.json","primary-record.json",
       "obsidian-registration.json","cohort.json","manifest.json"},
       {"journal.json","unit","launcher","plugin-selection.json","resources-record.json",
        "overlay-record.json","primary-record.json","obsidian-registration.json","cohort.json",
        "native-plugin-plugin.yaml","native-plugin-__init__.py","manifest.json"})):
  raise CoreRuntimeError("journaled adapter update backup custody differs")
 manifest_raw=_projection_file(backup/"manifest.json",owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=4096)
 try: manifest=json.loads(manifest_raw)
 except (ValueError,TypeError): raise CoreRuntimeError("adapter update backup manifest is invalid") from None
 if (type(manifest) is not dict or manifest!=reference["files"] or set(manifest) not in {
     frozenset({
     "journal.json","unit","launcher","plugin-selection.json","resources-record.json",
     "overlay-record.json","primary-record.json","obsidian-registration.json","cohort.json"}),
     frozenset({"journal.json","unit","launcher","plugin-selection.json","resources-record.json",
     "overlay-record.json","primary-record.json","obsidian-registration.json","cohort.json",
     "native-plugin-plugin.yaml","native-plugin-__init__.py"})}):
  raise CoreRuntimeError("adapter update backup manifest is not journal-bound")
 contents={}
 for name,digest in manifest.items():
  data=_projection_file(backup/name,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
  if hashlib.sha256(data).hexdigest()!=digest: raise CoreRuntimeError("adapter update backup bytes changed")
  contents[name]=data
 try: prior=json.loads(contents["journal.json"])
 except (ValueError,TypeError): raise CoreRuntimeError("prior adapter update journal is invalid") from None
 if (type(prior) is not dict or prior.get("adapter_generation")!=reference["source_generation"]
     or prior.get("adapter_migration_state")!="active"
     or prior.get("state") not in {"installed","active"}):
  raise CoreRuntimeError("adapter update backup does not bind the prior native generation")
 try: selection=json.loads(contents["plugin-selection.json"])
 except (ValueError,TypeError): raise CoreRuntimeError("adapter update selection receipt is invalid") from None
 if selection!={"schema":1,"selection_sha256":prior.get("plugin_selection_sha256")}:
  raise CoreRuntimeError("adapter update backup does not bind the prior plugin selection")
 old_source=Path(prior.get("adapter_source",""))
 _validate_adapter_generation_path(old_source)
 allowed_prior_units={_unit(adapter_source=old_source),
                      _unit(startup_guard=False,adapter_source=old_source)}
 if prior.get("adapter_update_cohort_transaction_id"):
  allowed_prior_units.add(_unit(adapter_source=old_source,cohort_gate=True,
   backup_generation=_journal_adapter_backup_generation(prior)))
 if contents["unit"] not in allowed_prior_units or contents["launcher"]!=_launcher(adapter_source=old_source):
  raise CoreRuntimeError("prior adapter update backup is not the fixed service recipe")
 return prior,contents

def _validate_adapter_update_history(record):
 if (type(record) is not dict or record.get("adapter_update_state")!="active"
     or not isinstance(record.get("adapter_update_backup"),dict)):
  raise CoreRuntimeError("active adapter update history is incomplete")
 prior,_contents=_read_adapter_update_backup(record["adapter_update_backup"])
 reference=record["adapter_update_backup"]
 if (reference.get("source_generation")==record.get("adapter_generation")
     or record.get("adapter_update_previous_source")!=prior.get("adapter_source")
     or record.get("plugin_selection_sha256")!=prior.get("plugin_selection_sha256")):
  raise CoreRuntimeError("active adapter update history does not bind its prior generation and selection")

def _snapshot_adapter_update_bindings(*,core_source_generation):
 """Capture the exact old Resources, overlay, primary and optional vault custody."""
 resources=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
 try: discovery=json.loads(resources)
 except (ValueError,TypeError): raise CoreRuntimeError("current Resources discovery record is malformed") from None
 if (discovery.get("core_source_generation")!=core_source_generation
     or discovery.get("state")!="discovered" or discovery.get("functional") is not False
     or discovery.get("enabled") is not False or discovery.get("target_verified") is not False):
  raise CoreRuntimeError("current Resources discovery is not eligible for a source cohort")
 try: overlay=_projection_file(RESOURCES_SKILL_OVERLAYS/"active.json",owner=ROOT_UID,
                               group=ROOT_UID,mode=0o600,maximum=256*1024)
 except FileNotFoundError: overlay=b""
 try: primary=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
                               group=ROOT_UID,mode=0o600,maximum=64*1024)
 except FileNotFoundError: primary=b""
 try:
  prior_cohort=_projection_file(ADAPTER_UPDATE_COHORT,owner=ROOT_UID,
                                group=ROOT_UID,mode=0o400,maximum=128*1024)
 except FileNotFoundError:
  prior_cohort=b""
 from .remote import obsidian_owner_lifecycle as obsidian
 try:
  owner_root,owner_subject,registration_sha=obsidian.read_registration()
 except FileNotFoundError:
  registration=b""; registration_state="absent"; registration_sha=_ABSENT_DIGEST
  vault_sha=_ABSENT_DIGEST
 except Exception:
  raise CoreRuntimeError("current Obsidian registration custody is unavailable") from None
 else:
  if owner_root!=obsidian.OWNER_DATA_ROOT or not re.fullmatch(r"[0-9a-f]{64}",owner_subject):
   raise CoreRuntimeError("current Obsidian owner registration differs")
  registration=_projection_file(obsidian.OWNER_REGISTRATION,owner=ROOT_UID,group=ROOT_UID,
                                 mode=0o600,maximum=2048)
  if hashlib.sha256(registration).hexdigest()!=registration_sha:
   raise CoreRuntimeError("Obsidian registration changed during source preparation")
  vault_sha=_obsidian_vault_tree_sha256(obsidian.OWNER_DATA_ROOT/"obsidian-vault")
  registration_state="registered"
 return {"resources_record":resources,"overlay_record":overlay,
  "primary_record":primary,"prior_cohort":prior_cohort,
  "obsidian_registration":registration,"obsidian_registration_state":registration_state,
  "obsidian_registration_sha256":registration_sha,"obsidian_vault_tree_sha256":vault_sha,
  "resources_record_sha256":hashlib.sha256(resources).hexdigest(),
  "overlay_record_sha256":hashlib.sha256(overlay).hexdigest() if overlay else _ABSENT_DIGEST,
  "primary_record_sha256":hashlib.sha256(primary).hexdigest() if primary else _ABSENT_DIGEST}

def _read_adapter_overlay_snapshot():
 """Read exact overlay bytes/content without requiring the future base to match."""
 path=RESOURCES_SKILL_OVERLAYS/"active.json"
 try: raw=_projection_file(path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
 except FileNotFoundError: return None,{},None
 try:
  def unique(pairs):
   row={}
   for key,value in pairs:
    if key in row: raise ValueError
    row[key]=value
   return row
  record=json.loads(raw,object_pairs_hook=unique)
  if (type(record) is not dict or set(record)!={"schema","base_artifact_sha256","skills"}
      or type(record["schema"]) is not int or record["schema"]!=1
      or re.fullmatch(r"[0-9a-f]{64}",str(record["base_artifact_sha256"])) is None
      or type(record["skills"]) is not dict or len(record["skills"])>396): raise ValueError
  contents={}
  for skill_id,item in record["skills"].items():
   if (not isinstance(skill_id,str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",skill_id) is None
       or type(item) is not dict or set(item)!={"content_sha256","archive_sha256"}
       or any(not isinstance(item[key],str) or re.fullmatch(r"[0-9a-f]{64}",item[key]) is None
              for key in item)): raise ValueError
   content=_projection_file(RESOURCES_SKILL_OVERLAYS/(item["content_sha256"]+".bin"),
    owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
   if hashlib.sha256(content).hexdigest()!=item["content_sha256"]: raise ValueError
   contents[skill_id]=content
  return record,contents,raw
 except Exception:
  raise CoreRuntimeError("protected Resources overlay snapshot is malformed") from None

def _obsidian_vault_tree_sha256(root):
 """Hash only regular, selected-owner vault bytes without following links."""
 root=Path(root)
 try: root_info=root.lstat()
 except FileNotFoundError: raise CoreRuntimeError("registered Obsidian vault is missing") from None
 if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=1000 or
     stat.S_IMODE(root_info.st_mode)&0o077):
  raise CoreRuntimeError("registered Obsidian vault root custody differs")
 rows=[]; total=0
 for base,dirs,names in os.walk(root,topdown=True,followlinks=False):
  base_path=Path(base)
  dirs.sort(); names.sort()
  for name in tuple(dirs):
   path=base_path/name; info=path.lstat()
   if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=1000 or
       stat.S_IMODE(info.st_mode)&0o022 or path.is_symlink()):
    raise CoreRuntimeError("Obsidian vault directory custody differs")
   rows.append({"path":path.relative_to(root).as_posix()+"/","mode":stat.S_IMODE(info.st_mode)})
  for name in names:
   path=base_path/name; info=path.lstat()
   if (not stat.S_ISREG(info.st_mode) or info.st_uid!=1000 or info.st_nlink!=1
       or path.is_symlink() or info.st_size>8*1024*1024):
    raise CoreRuntimeError("Obsidian vault member custody differs")
   data=_projection_file(path,owner=1000,group=info.st_gid,mode=stat.S_IMODE(info.st_mode),
                         maximum=8*1024*1024)
   total+=len(data)
   if total>64*1024*1024 or len(rows)>=20000:
    raise CoreRuntimeError("Obsidian vault snapshot exceeds its fixed bound")
   rows.append({"path":path.relative_to(root).as_posix(),"mode":stat.S_IMODE(info.st_mode),
                "size_bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
 return hashlib.sha256(_canonical_json(rows)).hexdigest()

def _verify_root_import_dispatch_source(adapter_generation,core_source_generation):
 """Recheck the exact helper, Hermes source and PM interpreter before owner effects."""
 _validate_adapter_source_path()
 if _identity(verify_python_version=False).get("commit")!=COMMIT:
  raise CoreRuntimeError("pinned Hermes identity changed before the owner importer")
 if _core_source_generation()!=core_source_generation:
  raise CoreRuntimeError("pinned Hermes Core source changed before the owner importer")
 from .remote import core_gateway_inspector as inspector
 if inspector._current_native_adapter_generation(deadline=time.monotonic()+20.0)!=adapter_generation:
  raise CoreRuntimeError("fixed installer adapter generation changed before the owner importer")
 if (_validated_executable(RUNUSER,{ROOT_UID})!=RUNUSER
     or _validated_executable(PYTHON,{1000})!=PYTHON
     or not PYTHON.is_symlink() or os.readlink(PYTHON)!=PYTHON_LINK_TARGET
     or PYTHON.resolve(strict=True)!=PYTHON_REAL
     or _digest(PYTHON_REAL)!=PYTHON_SHA256
     or _digest(PYTHON.parent.parent/"pyvenv.cfg")!=PYVENV_CFG_SHA256):
  raise CoreRuntimeError("fixed Root runuser or Hermes PM interpreter changed")

def _root_runuser_executable_identity():
 """Pin the fixed runuser executable before spawning its privileged child."""
 if (_validated_executable(RUNUSER,{ROOT_UID})!=RUNUSER
     or os.geteuid()!=ROOT_UID):
  raise CoreRuntimeError("fixed Root runuser executable custody differs")
 resolved=RUNUSER.resolve(strict=True); info=resolved.stat()
 if (info.st_uid!=ROOT_UID or not stat.S_ISREG(info.st_mode)
     or not info.st_mode&0o111):
  raise CoreRuntimeError("fixed Root runuser executable custody differs")
 return (info.st_dev,info.st_ino)

def _root_runuser_pipe_identity(process,argv,pipe_fd,expected_executable):
 """Capture one root-launched runuser parent and its inherited anonymous pipe."""
 if (os.geteuid()!=ROOT_UID or not isinstance(process,subprocess.Popen)
     or type(process.pid) is not int or process.pid<=1 or process.poll() is not None
     or not hasattr(os,"pidfd_open")):
  raise CoreRuntimeError("fixed Root runuser child is unavailable")
 pipe=os.fstat(pipe_fd)
 if not stat.S_ISFIFO(pipe.st_mode) or pipe.st_uid!=ROOT_UID:
  raise CoreRuntimeError("Root importer stdin is not its anonymous root-owned pipe")
 runuser=RUNUSER.resolve(strict=True); expected_exe=runuser.stat()
 if ((expected_exe.st_dev,expected_exe.st_ino)!=expected_executable
     or expected_exe.st_uid!=ROOT_UID or not stat.S_ISREG(expected_exe.st_mode)
     or not expected_exe.st_mode&0o111):
  raise CoreRuntimeError("fixed runuser executable custody differs")
 pidfd=os.pidfd_open(process.pid,0)
 identity={"pid":process.pid,"root_pid":os.getpid(),"pidfd":pidfd,
  "argv":tuple(os.fsencode(item) for item in argv),"exe_dev":expected_exe.st_dev,
  "exe_ino":expected_exe.st_ino,"pipe_dev":pipe.st_dev,"pipe_ino":pipe.st_ino}
 try:
  _assert_root_runuser_pipe_identity(process,identity,pipe_fd)
  first=_root_runuser_proc_snapshot(process,identity,pipe_fd)
  _assert_root_runuser_pipe_identity(process,identity,pipe_fd)
  second=_root_runuser_proc_snapshot(process,identity,pipe_fd)
  if first!=second:
   raise CoreRuntimeError("fixed Root runuser parent changed during capture")
  identity["snapshot"]=second
  return identity
 except BaseException:
  os.close(pidfd)
  raise

def _root_runuser_proc_snapshot(process,identity,pipe_fd):
 pid=identity["pid"]; proc=Path("/proc")/str(pid)
 stat_text=(proc/"stat").read_text(); close=stat_text.rfind(")")
 fields=stat_text[close+1:].split() if close>=0 else []
 if len(fields)<20: raise CoreRuntimeError("Root runuser process identity is unavailable")
 state=fields[0]; ppid=int(fields[1]); process_group=int(fields[2]); session=int(fields[3]); start_ticks=fields[19]
 values={line.split(":",1)[0]:line.split(":",1)[1].split()
  for line in (proc/"status").read_text().splitlines() if ":" in line}
 actual_argv=(proc/"cmdline").read_bytes().split(b"\0")
 if actual_argv and actual_argv[-1]==b"": actual_argv.pop()
 comm=(proc/"comm").read_text().strip()
 exe=(proc/"exe").stat()
 pipe=os.fstat(pipe_fd)
 proc_stdin=proc/"fd"/"0"
 stdin_target=os.readlink(proc_stdin)
 stdin_stat=proc_stdin.stat()
 if (state in {"Z","X"} or ppid!=identity["root_pid"]
     or process_group!=pid or session!=pid or not start_ticks.isdecimal()
     or values.get("Uid")!=["0"]*4 or values.get("Gid")!=["0"]*4 or comm!="runuser"
     or tuple(actual_argv)!=identity["argv"]
     or (exe.st_dev,exe.st_ino,exe.st_uid)!=(identity["exe_dev"],identity["exe_ino"],ROOT_UID)
     or not stat.S_ISFIFO(stdin_stat.st_mode) or stdin_stat.st_uid!=ROOT_UID
     or (stdin_stat.st_dev,stdin_stat.st_ino)!=(pipe.st_dev,pipe.st_ino)
     or stdin_target!=f"pipe:[{pipe.st_ino}]"
     or (pipe.st_dev,pipe.st_ino,pipe.st_uid)!=(identity["pipe_dev"],identity["pipe_ino"],ROOT_UID)):
  raise CoreRuntimeError("Root runuser parent, command, or inherited pipe changed")
 return (start_ticks,ppid,process_group,session,comm,tuple(actual_argv),
  exe.st_dev,exe.st_ino,stdin_target,stdin_stat.st_dev,stdin_stat.st_ino)

def _assert_root_runuser_pipe_identity(process,identity,pipe_fd):
 if (process.pid!=identity["pid"] or os.getpid()!=identity["root_pid"]
     or process.poll() is not None):
  raise CoreRuntimeError("fixed Root runuser process exited before its frame")
 poller=select.poll(); poller.register(identity["pidfd"],select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 current=_root_runuser_proc_snapshot(process,identity,pipe_fd)
 expected=identity.get("snapshot",current)
 if poller.poll(0) or current!=expected:
  raise CoreRuntimeError("fixed Root runuser PIDFD or parent identity changed")

def _assert_root_runuser_dispatch_complete(process,identity):
 poller=select.poll(); poller.register(identity["pidfd"],select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 if process.returncode is None or not poller.poll(0):
  raise CoreRuntimeError("fixed Root runuser process did not exit under its retained PIDFD")

def _terminate_root_runuser_group(process,identity):
 """Reap only the isolated session created for a failed fixed runuser operation."""
 if process is None: return
 try:
  if identity is not None:
   # The isolated process group may outlive its runuser leader if the owner
   # interpreter fails.  Its PID cannot be reused while members remain.
   try: os.killpg(identity["pid"],signal.SIGKILL)
   except ProcessLookupError: pass
  elif process.poll() is None:
   os.killpg(process.pid,signal.SIGKILL)
  process.communicate(timeout=5)
 except (OSError,subprocess.TimeoutExpired):
  try: process.kill()
  except OSError: pass
  try: process.communicate(timeout=2)
  except Exception: pass

def _require_bounded_helper_import_output(returncode,stdout,stderr):
 """Accept only a complete bounded fixed-importer response and diagnostics."""
 if (type(returncode) is not int or returncode!=0
     or type(stdout) is not bytes or len(stdout)>_HELPER_IMPORT_STDOUT_LIMIT
     or type(stderr) is not bytes or len(stderr)>_HELPER_IMPORT_STDERR_LIMIT):
  raise CoreRuntimeError("helper-only importer refused the root-selected transition")

def _run_same_materialization_import(prepared,next_archive,old_archive,backup_name):
 """Consume the root seal at the fixed root→runuser importer boundary."""
 if (os.geteuid()!=ROOT_UID or not verify_prepared_same_materialization_transition(prepared)
     or not isinstance(backup_name,str)
     or re.fullmatch(r"\.jarvis-resources-skills-helper-transition-[0-9a-f]{32}",backup_name) is None
     or hashlib.sha256(next_archive).hexdigest()!=prepared.new_artifact_sha256
     or hashlib.sha256(old_archive).hexdigest()!=prepared.old_artifact_sha256
     or len(next_archive)>16*1024*1024 or len(old_archive)>16*1024*1024):
  raise CoreRuntimeError("prepared helper-only importer inputs are stale or unbounded")
 _validate_adapter_source_path()
 if (_validated_executable(RUNUSER,{ROOT_UID})!=RUNUSER
     or not _validated_executable(PYTHON,{1000}).is_absolute()):
  raise CoreRuntimeError("fixed helper-only importer executables differ")
 from .registry import manual_jarvis_skills as native
 new_manifest,new_files,new_helper=native._read_transition_archive(
  next_archive,prepared.new_artifact_sha256)
 old_manifest,old_files,_old_helper=native._read_transition_archive(
  old_archive,prepared.old_artifact_sha256)
 if (not native.verify_same_materialization_transition(
      old_manifest,old_files,new_manifest,new_files)
     or new_helper!=Path(native.__file__).read_bytes()
     or native._same_materialization_digests(new_manifest,new_files)!=(
      prepared.shared_manifest_sha256,prepared.shared_materialization_sha256,
      prepared.shared_member_count)):
  raise CoreRuntimeError("fixed importer archives differ from the sealed classifier")
 _verify_root_import_dispatch_source(prepared.new_adapter_generation,prepared.new_source_generation)
 argv=[str(RUNUSER),"-u","admin","--",str(PYTHON),"-P","-m",
  "hermes_installer.registry.manual_jarvis_skills","import-helper-transition",
  "--home",str(HERMES_HOME),"--next-sha256",prepared.new_artifact_sha256,
  "--previous-sha256",prepared.old_artifact_sha256,
  "--backup-name",backup_name,
  "--shared-manifest-sha256",prepared.shared_manifest_sha256,
  "--shared-materialization-sha256",prepared.shared_materialization_sha256,
  "--shared-member-count",str(prepared.shared_member_count)]
 frame=struct.pack(">QQ",len(next_archive),len(old_archive))+next_archive+old_archive
 env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":str(HOME),
  "HERMES_HOME":str(HERMES_HOME),"LANG":"C.UTF-8",
  "PYTHONPATH":str(Path(__file__).resolve().parents[1]),
  "PYTHONNOUSERSITE":"1","PYTHONDONTWRITEBYTECODE":"1"}
 read_fd,write_fd=os.pipe()
 process=None; dispatch=None; writer=None; write_error=[]
 try:
  if not claim_prepared_same_materialization_step(prepared,step="resources-import"):
   raise CoreRuntimeError("prepared helper-only import claim is stale or replayed")
  runuser_executable=_root_runuser_executable_identity()
  process=subprocess.Popen(argv,stdin=read_fd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   cwd="/",env=env,close_fds=True,pass_fds=(read_fd,),start_new_session=True)
  os.close(read_fd); read_fd=-1
  dispatch=_root_runuser_pipe_identity(process,argv,write_fd,runuser_executable)
  def send_frame():
   try:
    _assert_root_runuser_pipe_identity(process,dispatch,write_fd)
    view=memoryview(frame)
    while view:
     written=os.write(write_fd,view)
     if written<=0: raise OSError("helper-only importer pipe closed")
     view=view[written:]
   except Exception as exc: write_error.append(exc)
   finally:
    try: os.close(write_fd)
    except OSError: pass
  writer=threading.Thread(target=send_frame,name="core-resources-transition-pipe",daemon=True)
  writer.start()
  try: stdout,stderr=process.communicate(timeout=300)
  except subprocess.TimeoutExpired:
   _terminate_root_runuser_group(process,dispatch); writer.join(timeout=1)
   raise CoreRuntimeError("helper-only importer exceeded its fixed deadline") from None
  writer.join(timeout=1)
  _assert_root_runuser_dispatch_complete(process,dispatch)
  if writer.is_alive() or write_error:
   raise CoreRuntimeError("helper-only importer input pipe did not complete exactly")
  _require_bounded_helper_import_output(process.returncode,stdout,stderr)
  try:
   def unique_result(pairs):
    value={}
    for key,item in pairs:
     if key in value: raise ValueError
     value[key]=item
    return value
   result=json.loads(stdout,object_pairs_hook=unique_result)
   generation=HERMES_HOME/"skills"/native._GENERATION
   backup_value=result.get("previous_generation_backup") if type(result) is dict else None
   backup=Path(backup_value) if isinstance(backup_value,str) else Path("/")
   expected_skills=sorted(row["skill_id"] for row in new_manifest["skill_members"])
   expected_profiles=sorted(row["source_id"] for row in new_manifest["profile_members"])
   expected_next_step=("Run the pinned Hermes skill list/view probe; qualify model-selected use "
                       "and non-skill integrations separately.")
   if (type(result) is not dict or result.get("state")!="staged"
       or result.get("materialized") is not True or result.get("discovered") is not False
       or result.get("artifact_sha256")!=prepared.new_artifact_sha256
       or result.get("generation_path")!=str(generation)
       or result.get("skills")!=expected_skills
       or result.get("profiles_preserved_internal")!=expected_profiles
       or type(result.get("next_step")) is not str
       or len(result["next_step"].encode("utf-8"))>256
       or result["next_step"]!=expected_next_step
       or result.get("previous_artifact_sha256")!=prepared.old_artifact_sha256
       or set(result)!={"state","materialized","discovered","artifact_sha256",
        "generation_path","skills","profiles_preserved_internal","next_step",
        "previous_generation_backup","previous_artifact_sha256"}
       or backup.parent!=HERMES_HOME or backup==generation or backup.is_symlink()
       or backup.name!=backup_name):
    raise ValueError
   _hash_generation_tree(HERMES_HOME,new_manifest,new_files,prepared.new_artifact_sha256)
   _hash_generation_tree(HERMES_HOME,old_manifest,old_files,prepared.old_artifact_sha256,
                         target_path=backup)
  except (TypeError,ValueError,UnicodeDecodeError):
   raise CoreRuntimeError("helper-only importer result is malformed") from None
  return result
 finally:
  if process is not None and process.poll() is None:
   _terminate_root_runuser_group(process,dispatch)
  if writer is not None: writer.join(timeout=1)
  if dispatch is not None: os.close(dispatch["pidfd"])
  if read_fd>=0: os.close(read_fd)
  try: os.close(write_fd)
  except OSError: pass

def _capture_adapter_service_process(source,adapter_generation,core_generation):
 """Hold the current systemd MainPID across the complete source handoff."""
 pid_text=_run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()
 try: pid=int(pid_text)
 except ValueError: raise CoreRuntimeError("owned adapter MainPID is unavailable") from None
 if pid<=1 or not hasattr(os,"pidfd_open"):
  raise CoreRuntimeError("owned adapter process PIDFD is unavailable")
 pidfd=os.pidfd_open(pid,0)
 try:
  poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
  evidence,identity=_adapter_process_identity(source,adapter_generation,core_generation,pid)
  if (poller.poll(0) or not _owned_listener_pidfd(adapter_source=source)
      or _run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()!=str(pid)):
   raise CoreRuntimeError("journal-owned adapter process changed during PIDFD capture")
  return pidfd,pid,evidence,identity
 except BaseException:
  os.close(pidfd)
  raise

def _stop_captured_adapter_process(pidfd,pid,source,adapter_generation,core_generation,identity):
 """Stop only the exact process held from old-source readback preparation."""
 poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 evidence,current=_adapter_process_identity(source,adapter_generation,core_generation,pid)
 if (current!=identity or poller.poll(0)
     or _run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()!=str(pid)
     or not _owned_listener_pidfd(adapter_source=source)):
  raise CoreRuntimeError("captured old adapter process changed before stop")
 _run(["systemctl","stop",SERVICE])
 poller.poll(30_000)
 if (not poller.poll(0)
     or _run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active"
     or _run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip() not in {"","0"}
     or _owned_listener(adapter_source=source)):
  raise CoreRuntimeError("captured old adapter process did not stop")

def _make_adapter_update_reconstruction(old_base,new_base,old_archive,overlay,contents,
                                        overlay_raw,old_marker,old_discovery):
 """Derive one active-overlay chain or the exact ordinary no-overlay base pair."""
 from .registry import manual_jarvis_skills as native
 from .registry import resources_skill_overlay as transform
 old_manifest,old_files=native._read_artifact(old_archive,hashlib.sha256(old_archive).hexdigest())
 new_manifest,new_files,new_helper=native._read_transition_archive(new_base,
  hashlib.sha256(new_base).hexdigest())
 if (not native.verify_same_materialization_transition(old_manifest,old_files,new_manifest,new_files)
     or new_helper!=Path(native.__file__).read_bytes()):
  raise CoreRuntimeError("candidate Resources artifacts are not the exact helper-only pair")
 if overlay_raw is None:
  if overlay is not None or contents or old_base!=old_archive:
   raise CoreRuntimeError("absent owner overlay does not match the exact old base")
  shared_manifest,shared_tree,count=native._same_materialization_digests(new_manifest,new_files)
  old_non=dict(old_manifest); old_non.pop("installer",None)
  new_non=dict(new_manifest); new_non.pop("installer",None)
  return _BaseOnlyReconstruction(new_base,hashlib.sha256(old_base).hexdigest(),
   hashlib.sha256(new_base).hexdigest(),hashlib.sha256(old_archive).hexdigest(),
   hashlib.sha256(new_base).hexdigest(),_ABSENT_DIGEST,(),
   hashlib.sha256(native._canonical_json(new_non)).hexdigest(),
   hashlib.sha256(native._canonical_json(new_non)).hexdigest(),shared_tree,count)
 result=transform.reconstruct_helper_only_overlay_transition(
  old_base,new_base,old_archive,overlay_raw,contents)
 if (result.old_installed_journal_sha256 if hasattr(result,"old_installed_journal_sha256") else None) is not None:
  raise CoreRuntimeError("overlay reconstruction unexpectedly supplied authority")
 return result

def _adapter_update_reconstruction_row(result,*,cohort_id,phase,old_core,new_core,
                                       old_recipe,new_recipe,old_marker,new_marker=None,
                                       old_discovery,new_discovery=None):
 row={"schema":1,
  "purpose":"helper-only-base-reconstruction" if result.overlay_journal_sha256==_ABSENT_DIGEST
    else "helper-only-overlay-reconstruction",
  "cohort_transaction_id":cohort_id,"owner_uid":1000,"home_role":"jarvis-primary-home",
  "phase":phase,"old_base_artifact_sha256":result.old_base_artifact_sha256,
  "new_base_artifact_sha256":result.new_base_artifact_sha256,
  "old_composed_artifact_sha256":result.old_composed_artifact_sha256,
  "new_composed_artifact_sha256":result.new_composed_artifact_sha256,
  "overlay_journal_sha256":result.overlay_journal_sha256,
  "overlay_contents":[{"skill_id":name,"content_sha256":digest}
   for name,digest in result.overlay_contents],
  "base_non_installer_manifest_sha256":result.base_non_installer_manifest_sha256,
  "composed_non_installer_manifest_sha256":result.composed_non_installer_manifest_sha256,
  "materialized_tree_sha256":result.materialized_tree_sha256,
  "old_installed_journal_sha256":old_marker,
  "new_installed_journal_sha256":new_marker,
  "old_discovery_sha256":old_discovery,"new_discovery_sha256":new_discovery,
  "old_core_source_generation":old_core,"new_core_source_generation":new_core,
  "old_source_recipe_sha256":old_recipe,"new_source_recipe_sha256":new_recipe}
 return row

def _write_resources_cas_artifact(archive,artifact_sha):
 if hashlib.sha256(archive).hexdigest()!=artifact_sha:
  raise CoreRuntimeError("prepared Resources CAS artifact digest differs")
 _ensure_dir(RESOURCES_CAS,ROOT_UID,ROOT_UID,0o700)
 path=RESOURCES_CAS/(artifact_sha+".zip")
 try:
  existing=_projection_file(path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 except FileNotFoundError:
  _atomic(path,archive,0o600,ROOT_UID,ROOT_UID)
 else:
  if existing!=archive: raise CoreRuntimeError("Resources immutable CAS digest collision")

def _current_old_update_check(*,journal_raw,resources_raw,overlay_raw,primary_raw,
                              registration_raw,source,adapter_generation,core_generation,
                              process_identity,pid):
 if (_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)!=journal_raw
     or _projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)!=resources_raw):
  return False
 try: current_overlay=_projection_file(RESOURCES_SKILL_OVERLAYS/"active.json",owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=256*1024)
 except FileNotFoundError: current_overlay=None
 if current_overlay!=(overlay_raw or None): return False
 try: current_primary=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=64*1024)
 except FileNotFoundError: current_primary=None
 if current_primary!=(primary_raw or None): return False
 from .remote import obsidian_owner_lifecycle as obsidian
 try:
  current_registration=_projection_file(obsidian.OWNER_REGISTRATION,owner=ROOT_UID,
   group=ROOT_UID,mode=0o600,maximum=2048)
 except FileNotFoundError: current_registration=None
 if current_registration!=(registration_raw or None): return False
 try:
  _evidence,current_identity=_adapter_process_identity(source,adapter_generation,core_generation,pid)
  from hermes_installer.remote.core_gateway_inspector import _current_native_adapter_generation
  return bool(current_identity==process_identity
   and _current_native_adapter_generation(deadline=time.monotonic()+35.0)==adapter_generation
   and _core_source_generation()==core_generation)
 except Exception: return False

def _stop_owned_core_for_adapter_update(allowed_sources):
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 if active not in {"active","inactive","failed"}:
  raise CoreRuntimeError("owned service state is ambiguous; refusing adapter update")
 pidfd=None
 try:
  if active=="active":
   pid_text=_run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()
   pid=int(pid_text)
   if pid<=1 or not hasattr(os,"pidfd_open"):
    raise CoreRuntimeError("active core PIDFD is unavailable; refusing update stop")
   pidfd=os.pidfd_open(pid,0)
   poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
   if poller.poll(0): raise CoreRuntimeError("active core PIDFD is already exited")
   source=next((source for source in allowed_sources if _owned_listener(adapter_source=source)),None)
   if (source is None
       or _run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()!=str(pid)
       or poller.poll(0)):
    raise CoreRuntimeError("active process is not the journal-owned adapter core; refusing update stop")
  _run(["systemctl","stop",SERVICE])
  if ((pidfd is not None and not poller.poll(0))
      or _run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active"
      or _run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip() not in {"","0"}
      or any(_owned_listener(adapter_source=source) for source in allowed_sources)):
   raise CoreRuntimeError("owned core did not stop cleanly; adapter update halted")
 finally:
  if pidfd is not None: os.close(pidfd)

def _restore_adapter_update_owner_generation(cohort):
 """Use the fixed root→runuser restore operation for an interrupted owner CAS."""
 if os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get():
  raise CoreRuntimeError("owner-generation restore requires the held Root recovery lock")
 from .registry import manual_jarvis_skills as native
 target=HERMES_HOME/"skills"/native._GENERATION
 old_sha=cohort["old_artifact_sha256"]; new_sha=cohort["new_artifact_sha256"]
 old_archive=_projection_file(RESOURCES_CAS/(old_sha+".zip"),owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 new_archive=_projection_file(RESOURCES_CAS/(new_sha+".zip"),owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 old_manifest,old_files,_old_helper=native._read_transition_archive(old_archive,old_sha)
 new_manifest,new_files,_new_helper=native._read_transition_archive(new_archive,new_sha)
 target_ok=False
 try:
  _hash_generation_tree(HERMES_HOME,old_manifest,old_files,old_sha); target_ok=True
 except CoreRuntimeError: pass
 if target_ok:
  return
 _hash_generation_tree(HERMES_HOME,new_manifest,new_files,new_sha)
 _verify_root_import_dispatch_source(cohort["new_adapter_generation"],
  cohort["new_core_source_generation"])
 name=cohort["owner_generation_backup_name"]
 shared_manifest,shared_materialization,shared_count=_same_materialization_digests(
  native,new_manifest,new_files)
 argv=[str(RUNUSER),"-u","admin","--",str(PYTHON),"-P","-m",
  "hermes_installer.registry.manual_jarvis_skills","restore-helper-transition",
  "--home",str(HERMES_HOME),"--current-sha256",new_sha,"--restore-sha256",old_sha,
  "--backup-name",name,"--shared-manifest-sha256",shared_manifest,
  "--shared-materialization-sha256",shared_materialization,
  "--shared-member-count",str(shared_count)]
 frame=struct.pack(">QQ",len(new_archive),len(old_archive))+new_archive+old_archive
 env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":str(HOME),
  "HERMES_HOME":str(HERMES_HOME),"LANG":"C.UTF-8",
  "PYTHONPATH":str(Path(__file__).resolve().parents[1]),
  "PYTHONNOUSERSITE":"1","PYTHONDONTWRITEBYTECODE":"1"}
 if (_validated_executable(RUNUSER,{ROOT_UID})!=RUNUSER
     or _validated_executable(PYTHON,{1000})!=PYTHON):
  raise CoreRuntimeError("fixed owner-generation rollback executables differ")
 rfd,wfd=os.pipe()
 process=None; dispatch=None; writer=None; write_error=[]
 try:
  runuser_executable=_root_runuser_executable_identity()
  process=subprocess.Popen(argv,stdin=rfd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   cwd="/",env=env,close_fds=True,pass_fds=(rfd,),start_new_session=True)
  os.close(rfd); rfd=-1
  dispatch=_root_runuser_pipe_identity(process,argv,wfd,runuser_executable)
  def write_frame():
   try:
    _assert_root_runuser_pipe_identity(process,dispatch,wfd)
    view=memoryview(frame)
    while view:
     sent=os.write(wfd,view)
     if sent<=0: raise OSError("owner generation rollback pipe closed")
     view=view[sent:]
   except Exception as exc: write_error.append(exc)
   finally:
    try: os.close(wfd)
    except OSError: pass
  writer=threading.Thread(target=write_frame,name="core-resources-rollback-pipe",daemon=True)
  writer.start()
  try: stdout,stderr=process.communicate(timeout=180)
  except subprocess.TimeoutExpired:
   _terminate_root_runuser_group(process,dispatch); writer.join(timeout=1)
   raise CoreRuntimeError("owner generation rollback exceeded its fixed deadline") from None
  writer.join(timeout=1)
  _assert_root_runuser_dispatch_complete(process,dispatch)
  if writer.is_alive() or write_error or process.returncode or len(stdout)>8192 or len(stderr)>8192:
   raise CoreRuntimeError("owner generation rollback operation failed")
  try: result=json.loads(stdout)
  except (ValueError,TypeError): raise CoreRuntimeError("owner generation rollback result is malformed") from None
  if (type(result) is not dict or result.get("state")!="restored"
      or result.get("artifact_sha256")!=old_sha
      or result.get("generation_path")!=str(target)
      or result.get("retained_artifact_sha256")!=new_sha
      or result.get("retained_generation_backup")!=str(target.parent/name)
      or set(result)!={"state","artifact_sha256","generation_path",
       "retained_generation_backup","retained_artifact_sha256"}):
   raise CoreRuntimeError("owner generation rollback receipt does not bind the prior bytes")
  _hash_generation_tree(HERMES_HOME,old_manifest,old_files,old_sha)
  return result
 finally:
  if process is not None and process.poll() is None:
   _terminate_root_runuser_group(process,dispatch)
  if writer is not None: writer.join(timeout=1)
  if dispatch is not None: os.close(dispatch["pidfd"])
  if rfd>=0: os.close(rfd)
  try: os.close(wfd)
  except OSError: pass

def _same_materialization_digests(native,manifest,files):
 return native._same_materialization_digests(manifest,files)

def _check_adapter_cohort_rollback_currentness(cohort,prior,contents):
 """Refuse recovery if a binding changed outside this exact cohort's writes."""
 old_journal=contents["journal.json"]
 journal_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 journal_hash=hashlib.sha256(journal_raw).hexdigest()
 allowed_journals={hashlib.sha256(old_journal).hexdigest()}
 for key in ("starting_journal_sha256","new_journal_sha256"):
  if cohort.get(key): allowed_journals.add(cohort[key])
 if journal_hash not in allowed_journals:
  raise CoreRuntimeError("current Core journal is outside the exact source cohort recovery states")
 resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
  mode=0o600,maximum=16*1024)
 allowed_resources={hashlib.sha256(contents["resources-record.json"]).hexdigest()}
 for key in ("pre_switch_resources_record_sha256","starting_resources_record_sha256",
             "new_resources_record_sha256"):
  if cohort.get(key): allowed_resources.add(cohort[key])
 if hashlib.sha256(resources_raw).hexdigest() not in allowed_resources:
  raise CoreRuntimeError("current Resources receipt is outside the exact source cohort recovery states")
 try: overlay_now=_projection_file(RESOURCES_SKILL_OVERLAYS/"active.json",owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=256*1024)
 except FileNotFoundError: overlay_now=b""
 if overlay_now!=contents["overlay-record.json"]:
  raise CoreRuntimeError("owner Resources overlay changed during source cohort recovery")
 from .remote import obsidian_owner_lifecycle as obsidian
 try: registration_now=_projection_file(obsidian.OWNER_REGISTRATION,owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=2048)
 except FileNotFoundError: registration_now=b""
 if (registration_now!=contents["obsidian-registration.json"]
     or (registration_now and _obsidian_vault_tree_sha256(obsidian.OWNER_DATA_ROOT/"obsidian-vault")
         !=cohort["obsidian_vault_tree_sha256"])):
  raise CoreRuntimeError("Obsidian registration or vault changed during source cohort recovery")
 unit=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
 old_source=Path(prior["adapter_source"])
 allowed_units={contents["unit"],_unit(adapter_source=old_source,cohort_gate=True,
   backup_generation=cohort["old_adapter_generation"]),
                _unit(adapter_source=Path(cohort["new_source"]),cohort_gate=True,
   backup_generation=cohort["old_adapter_generation"])}
 if unit not in allowed_units:
  raise CoreRuntimeError("current unit is outside the exact guarded source recipes")
 launcher=_projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)
 if launcher not in {contents["launcher"],_launcher(adapter_source=Path(cohort["new_source"]))}:
  raise CoreRuntimeError("current launcher is outside the exact source recipes")
 transition=cohort.get("native_plugin_transition")
 if transition is None:
  if any(name in contents for name in _NATIVE_PLUGIN_BACKUP_NAMES.values()):
   raise CoreRuntimeError("native plugin backup exists without a journaled transition")
 else:
  _validate_native_plugin_transition_row(transition,cohort)
  old_members={name:contents[_NATIVE_PLUGIN_BACKUP_NAMES[name]] for name in _NATIVE_PLUGIN_FILES}
  new_members=_native_plugin_source_members(Path(cohort["new_source"]))
  if (_native_plugin_member_hashes(old_members)!=transition["old_members"]
      or _native_plugin_member_hashes(new_members)!=transition["new_members"]):
   raise CoreRuntimeError("native plugin source or immutable backup differs from the cohort")
  current_members=dict(_read_installed_native_resources_plugin_members().members)
  if any(current_members[name] not in (old_members[name],new_members[name])
         for name in _NATIVE_PLUGIN_FILES):
   raise CoreRuntimeError("installed native plugin pair is outside the exact rollback closure")
 old_primary=contents["primary-record.json"]
 try: current_primary=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=64*1024)
 except FileNotFoundError: current_primary=None
 if not old_primary:
  initial=cohort.get("initial_primary_transition")
  if initial is None:
   if current_primary is not None:
    raise CoreRuntimeError("primary adoption appeared during an unadopted source cohort")
  elif type(initial) is dict:
   stage_keys=("preparing_record_sha256","writing_record_sha256",
    "adopted_record_sha256","after_resources_record_sha256")
   unwritten_rollback=(initial.get("state")=="rolling-back"
    and all(initial.get(key) is None for key in stage_keys)
    and initial.get("owner_backup_sha256") is None)
   if unwritten_rollback:
    if current_primary is not None:
     raise CoreRuntimeError("unwritten initial-primary rollback found a manager record")
    from . import primary_prompt_manager as primary
    soul,signature=primary._read_soul(sys.modules[__name__])
    if (hashlib.sha256(soul).hexdigest()!=initial.get("prior_soul_sha256")
        or tuple(signature)!=tuple(initial.get("prior_soul_signature",()))):
     raise CoreRuntimeError("unwritten initial-primary rollback lost original owner SOUL")
   elif initial.get("state") in {"pending","preparing"} and initial.get("preparing_record_sha256") is None:
    if initial.get("state")=="pending" and current_primary is not None:
     raise CoreRuntimeError("initial primary journal appeared outside its exact staged transition")
    if initial.get("state")=="preparing" and current_primary is not None:
     try: current_row=json.loads(current_primary)
     except (ValueError,TypeError): raise CoreRuntimeError("initial primary journal is malformed") from None
     from . import primary_prompt_manager as primary
     soul,signature=primary._read_soul(sys.modules[__name__])
     if (current_row.get("state")!="preparing"
         or current_row.get("prior_soul_sha256")!=initial.get("prior_soul_sha256")
         or current_row.get("source_prompt_sha256")!=initial.get("source_prompt_sha256")
         or current_row.get("managed_block_sha256")!=initial.get("managed_block_sha256")
         or hashlib.sha256(soul).hexdigest() not in {initial.get("prior_soul_sha256"),
              initial.get("desired_soul_sha256")}
         or (hashlib.sha256(soul).hexdigest()==initial.get("prior_soul_sha256")
             and not _restored_soul_signature_matches(
              signature,initial.get("prior_soul_signature",())))):
      raise CoreRuntimeError("unrecorded initial primary stage does not match the armed exact transition")
     backup=primary._backup_read(sys.modules[__name__],current_row)
     if hashlib.sha256(backup).hexdigest()!=initial.get("prior_soul_sha256"):
      raise CoreRuntimeError("unrecorded initial primary backup differs from original owner SOUL")
   else:
    allowed_primary={initial.get("preparing_record_sha256"),initial.get("writing_record_sha256"),
     initial.get("adopted_record_sha256")}
    if current_primary is None:
     raise CoreRuntimeError("initial primary journal is outside its exact retained stage")
    try: current_row=json.loads(current_primary)
    except (ValueError,TypeError): raise CoreRuntimeError("initial primary journal is malformed") from None
    current_digest=hashlib.sha256(current_primary).hexdigest()
    one_ahead={"preparing":"writing","writing":"adopted"}.get(initial.get("state"))
    unrecorded_next=(current_digest not in allowed_primary and one_ahead is not None
      and current_row.get("state")==one_ahead
      and ((one_ahead=="writing" and initial.get("writing_record_sha256") is None)
       or (one_ahead=="adopted" and initial.get("adopted_record_sha256") is None)))
    if current_digest not in allowed_primary and not unrecorded_next:
     raise CoreRuntimeError("initial primary journal is outside its exact retained stage")
    from . import primary_prompt_manager as primary
    soul,signature=primary._read_soul(sys.modules[__name__])
    if (current_row.get("state") not in {"preparing","writing","adopted"}
        or current_row.get("prior_soul_sha256")!=initial.get("prior_soul_sha256")
        or current_row.get("artifact_sha256")!=cohort.get("new_artifact_sha256")
        or current_row.get("core_source_generation")!=cohort.get("new_core_source_generation")
        or current_row.get("source_prompt_sha256")!=initial.get("source_prompt_sha256")
        or current_row.get("managed_block_sha256")!=initial.get("managed_block_sha256")
        or hashlib.sha256(soul).hexdigest() not in {initial.get("prior_soul_sha256"),
             initial.get("desired_soul_sha256")}
        or (hashlib.sha256(soul).hexdigest()==initial.get("prior_soul_sha256")
             and not _restored_soul_signature_matches(
              signature,initial.get("prior_soul_signature",())))):
     raise CoreRuntimeError("initial primary stage or owner SOUL changed outside the retained cohort")
    backup=primary._backup_read(sys.modules[__name__],current_row)
    backup_sha=hashlib.sha256(backup).hexdigest()
    if backup_sha not in {initial.get("owner_backup_sha256"),initial.get("prior_soul_sha256")}:
     raise CoreRuntimeError("initial primary immutable backup changed outside the retained cohort")
  else:
   raise CoreRuntimeError("initial primary recovery row is malformed")
 elif current_primary!=old_primary:
  try:
   old_record=json.loads(old_primary); current_record=json.loads(current_primary)
   if (type(old_record) is not dict or type(current_record) is not dict
       or set(old_record)!=set(current_record)
       or old_record.get("state")!="adopted" or current_record.get("state")!="adopted"):
    raise ValueError
   expected=dict(old_record); expected["artifact_sha256"]=cohort["new_artifact_sha256"]
   timestamp=current_record.get("observed_at_utc")
   if not isinstance(timestamp,str): raise ValueError
   datetime.fromisoformat(timestamp.replace("Z","+00:00"))
   expected["observed_at_utc"]=timestamp
   if current_record!=expected: raise ValueError
  except (ValueError,TypeError):
   raise CoreRuntimeError("primary journal changed beyond the exact metadata-only cohort rebind") from None

def _restore_adapter_update_backup(reference,*,allowed_sources):
 prior,contents=_read_adapter_update_backup(reference)
 try: cohort,cohort_raw=_read_adapter_update_cohort(allow_absent=True)
 except CoreRuntimeError: raise
 if cohort is not None:
  if (cohort.get("cohort_transaction_id") not in str(cohort.get("owner_generation_backup_name"))
      or cohort.get("old_adapter_generation")!=reference.get("source_generation")):
   raise CoreRuntimeError("adapter recovery backup reference does not match the active cohort")
  _check_adapter_cohort_rollback_currentness(cohort,prior,contents)
 if cohort is not None and cohort["phase"]!="rolling-back":
  rolling=dict(cohort); rolling["phase"]="rolling-back"
  initial=rolling.get("initial_primary_transition")
  if type(initial) is dict:
   # Even a still-pending primary transition needs a journaled rollback phase:
   # recovery validates that state before it can prove the original SOUL and
   # absence of a primary record.
   initial=dict(initial); initial["state"]="rolling-back"
   rolling["initial_primary_transition"]=initial
  reconstruction=dict(rolling["reconstruction"]); reconstruction["phase"]="rolling-back"
  rolling["reconstruction"]=reconstruction
  rolling["reconstruction_sha256"]=hashlib.sha256(_canonical_json(reconstruction)).hexdigest()
  cohort_raw=_write_adapter_update_cohort(rolling,expected_raw=cohort_raw)
  cohort=rolling
 _stop_owned_core_for_adapter_update(allowed_sources)
 transition=cohort.get("native_plugin_transition") if cohort is not None else None
 if transition is not None:
  old_members={name:contents[_NATIVE_PLUGIN_BACKUP_NAMES[name]] for name in _NATIVE_PLUGIN_FILES}
  new_members=_native_plugin_source_members(Path(cohort["new_source"]))
  snapshot=_read_installed_native_resources_plugin_members()
  plugin_state={"old_source":cohort["old_source"],"new_source":cohort["new_source"],
   "old_adapter_generation":cohort["old_adapter_generation"],
   "new_adapter_generation":cohort["new_adapter_generation"],
   "old_core_source_generation":cohort["old_core_source_generation"],
   "plugin_selection_sha256":transition["plugin_selection_sha256"],
   "old_members":old_members,"new_members":new_members,
   "old_signatures":dict(snapshot.signatures),"old_pidfd":None,
   "cohort_raw":cohort_raw}
  plugin_token=_NATIVE_PLUGIN_TRANSITION_STATE.set(plugin_state)
  try:
   _run_native_plugin_transition("restore")
  finally:
   _NATIVE_PLUGIN_TRANSITION_STATE.reset(plugin_token)
 # Keep the deny-by-default cohort guard in place while restoring the old
 # launcher and journal. Restore the exact former unit last, so reboot can
 # never combine a guardless launcher with the new/preparing journal.
 guarded=_unit(adapter_source=Path(prior["adapter_source"]),cohort_gate=True,
  backup_generation=cohort["old_adapter_generation"] if cohort is not None else
   _journal_adapter_backup_generation(prior))
 _atomic_replace(UNIT,guarded,0o644,ROOT_UID,ROOT_UID)
 _run(["systemctl","daemon-reload"])
 if (_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)!=guarded
     or _owned_unit_loaded() is not True):
  raise CoreRuntimeError("rollback deny-by-default unit did not load")
 if cohort is not None:
  # Restore only the exact saved binding bytes. The current primary must still
  # carry the adopted SOUL bytes; a later owner edit is a conflict, never a
  # reason to overwrite their prompt.
  old_primary=contents["primary-record.json"]
  try: current_primary=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
   group=ROOT_UID,mode=0o600,maximum=64*1024)
  except FileNotFoundError: current_primary=None
  if old_primary:
   from . import primary_prompt_manager as primary
   prior_primary=primary._read_record(sys.modules[__name__])
   try: old_primary_record=json.loads(old_primary)
   except (ValueError,TypeError): raise CoreRuntimeError("saved primary binding is malformed") from None
   if (prior_primary is None or prior_primary.get("state")!="adopted"
       or old_primary_record.get("state")!="adopted"):
    raise CoreRuntimeError("saved adopted primary binding cannot be restored")
   soul,_signature=primary._read_soul(sys.modules[__name__])
   if hashlib.sha256(soul).hexdigest()!=old_primary_record.get("result_soul_sha256"):
    raise CoreRuntimeError("owner SOUL changed after helper-only rebind; recovery preserves the conflict")
   backup=primary._backup_read(sys.modules[__name__],old_primary_record)
   if hashlib.sha256(backup).hexdigest()!=old_primary_record.get("owner_backup_name"):
    raise CoreRuntimeError("immutable prior SOUL backup changed during rollback")
   if current_primary!=old_primary:
    _atomic_replace(PRIMARY_PROMPT_JOURNAL,old_primary,0o600,ROOT_UID,ROOT_UID)
  elif cohort.get("initial_primary_transition") is not None:
   transition=_initial_primary_transition_row(cohort)
   if transition.get("state")!="rolling-back":
    raise CoreRuntimeError("initial primary recovery is not in its closed rollback phase")
   if current_primary is None:
    from . import primary_prompt_manager as primary
    soul,signature=primary._read_soul(sys.modules[__name__])
    if (hashlib.sha256(soul).hexdigest()!=transition.get("prior_soul_sha256")
        or not _restored_soul_signature_matches(
         signature,transition.get("prior_soul_signature",()))):
     raise CoreRuntimeError("initial primary record is absent but original owner SOUL is not restored")
   else:
    custody=_issue_initial_primary_rollback_custody(reference=reference,prior=prior,
     contents=contents,cohort=cohort,cohort_raw=_projection_file(ADAPTER_UPDATE_COHORT,
      owner=ROOT_UID,group=ROOT_UID,mode=0o400,maximum=128*1024))
    from . import primary_prompt_manager as primary
    primary.rollback_primary_prompt_for_starting_cohort(custody)
    verify_initial_primary_rollback_custody(custody)
    stage=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
     mode=0o600,maximum=64*1024)
    if hashlib.sha256(stage).hexdigest()!=custody.primary_stage_sha256:
     raise CoreRuntimeError("offline primary rollback changed its owned stage journal")
    _retain_initial_primary_stage(cohort["cohort_transaction_id"],stage)
    soul,signature=primary._read_soul(sys.modules[__name__])
    if (hashlib.sha256(soul).hexdigest()!=transition["prior_soul_sha256"]
        or not _restored_soul_signature_matches(
         signature,transition["prior_soul_signature"])):
     raise CoreRuntimeError("offline primary rollback did not restore exact original SOUL")
    PRIMARY_PROMPT_JOURNAL.unlink()
    _sync_directory(PRIMARY_PROMPT_JOURNAL.parent)
    try:
     _projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
      mode=0o600,maximum=64*1024)
     raise CoreRuntimeError("initial primary journal remained after exact rollback unlink")
    except FileNotFoundError: pass
  elif current_primary is not None:
   raise CoreRuntimeError("primary adoption appeared during an originally unadopted source cohort")
  # If recovery resumed after an earlier successful atomic exchange, accept
  # only the complete old generation. Otherwise the fixed restore helper must
  # prove A1 is still current before exchanging it for A0.
  from .registry import manual_jarvis_skills as native
  target=HERMES_HOME/"skills"/native._GENERATION
  old_archive=_projection_file(RESOURCES_CAS/(cohort["old_artifact_sha256"]+".zip"),
   owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
  old_manifest,old_files,_old_helper=native._read_transition_archive(
   old_archive,cohort["old_artifact_sha256"])
  try:
   _hash_generation_tree(HERMES_HOME,old_manifest,old_files,cohort["old_artifact_sha256"])
  except CoreRuntimeError:
   _restore_adapter_update_owner_generation(cohort)
  _atomic_replace(RESOURCES_RECORD,contents["resources-record.json"],0o600,ROOT_UID,ROOT_UID)
  old_resource=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
   mode=0o600,maximum=16*1024)
  if old_resource!=contents["resources-record.json"]:
   raise CoreRuntimeError("prior Resources discovery receipt did not restore exactly")
 _atomic_replace(LAUNCHER,contents["launcher"],0o755,ROOT_UID,ROOT_UID)
 _atomic_replace(JOURNAL,contents["journal.json"],0o600,ROOT_UID,ROOT_UID)
 prior_cohort=contents["cohort.json"]
 if prior_cohort:
  _atomic_replace(ADAPTER_UPDATE_COHORT,prior_cohort,0o400,ROOT_UID,ROOT_UID)
 else:
  try:
   current_cohort=_projection_file(ADAPTER_UPDATE_COHORT,owner=ROOT_UID,group=ROOT_UID,
                                   mode=0o400,maximum=128*1024)
  except FileNotFoundError: current_cohort=None
  if current_cohort is not None:
   ADAPTER_UPDATE_COHORT.unlink()
   _sync_directory(ADAPTER_UPDATE_COHORT.parent)
 _run(["systemctl","daemon-reload"])
 # Exact old unit is the final file restoration; its recipe again matches J0.
 _atomic_replace(UNIT,contents["unit"],0o644,ROOT_UID,ROOT_UID)
 _run(["systemctl","daemon-reload"])
 if not _owned_unit_loaded(): raise CoreRuntimeError("restored prior adapter unit is not journal-owned")
 _run(["systemctl","start",SERVICE]); _wait_for_listener()
 if not _owned_listener_pidfd(adapter_source=prior["adapter_source"]):
  raise CoreRuntimeError("prior journal-owned adapter process did not recover")
 from hermes_installer.remote.native_plugin_bootstrap import verify_native_resources_plugin_selection
 if getattr(verify_native_resources_plugin_selection(),"selection_sha256",None)!=prior["plugin_selection_sha256"]:
  raise CoreRuntimeError("native plugin selection changed during adapter update recovery")
 return prior

def _write_resources_record_bytes(archive,record):
 """Retain an actual verified CAS archive and its closed root receipt."""
 artifact=record.get("artifact_sha256") if type(record) is dict else None
 if (not isinstance(artifact,str) or re.fullmatch(r"[0-9a-f]{64}",artifact) is None
     or hashlib.sha256(archive).hexdigest()!=artifact):
  raise CoreRuntimeError("Resources receipt does not bind the selected immutable archive")
 _write_resources_cas_artifact(archive,artifact)
 raw=(json.dumps(record,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
 _atomic_replace(RESOURCES_RECORD,raw,0o600,ROOT_UID,ROOT_UID)
 if _projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
      mode=0o600,maximum=16*1024)!=raw:
  raise CoreRuntimeError("Resources discovery record readback differs")
 return raw

def _bind_resources_record_to_starting_journal(record,journal_raw):
 """Join a complete pre-stop native readback to its exact planned J_s bytes."""
 if (type(record) is not dict or type(journal_raw) is not bytes
     or not journal_raw.endswith(b"\n") or len(journal_raw)>64*1024):
  raise CoreRuntimeError("starting Resources/source join is malformed")
 try: journal=json.loads(journal_raw)
 except (ValueError,TypeError): raise CoreRuntimeError("starting source journal is malformed") from None
 if (type(journal) is not dict or journal.get("adapter_update_state")!="starting"
     or journal.get("adapter_update_cohort_transaction_id") is None
     or journal.get("core_source_generation")!=record.get("core_source_generation")
     or journal.get("adapter_source")!=str(ADAPTER_SOURCE)):
  raise CoreRuntimeError("starting source journal differs from the native Resources readback")
 result=dict(record)
 result["core_ownership_sha256"]=hashlib.sha256(journal_raw).hexdigest()
 return result

def _adapter_update_current_resource_payload(*,overlay_snapshot,reconstruction):
 """Run the fixed native loader and prove A1 while the old process is still held."""
 overlay_record,contents,overlay_raw=overlay_snapshot
 archive,record=_verified_resources_payload(
  _prepared_transition=(overlay_record,contents,overlay_raw,reconstruction))
 if (archive!=reconstruction.new_composed_archive
     or record.get("artifact_sha256")!=reconstruction.new_composed_artifact_sha256
     or record.get("core_source_generation")!=_core_source_generation()
     or record.get("state")!="discovered" or record.get("functional") is not False
     or record.get("enabled") is not False or record.get("target_verified") is not False):
  raise CoreRuntimeError("A1 source/discovery/native loader readback differs")
 return archive,record

def _run_root_coro(coroutine):
 """Run the fixed synchronous updater's bounded native coroutine without nesting loops."""
 import asyncio
 try: asyncio.get_running_loop()
 except RuntimeError: return asyncio.run(coroutine)
 result=[]; failure=[]
 def runner():
  try: result.append(asyncio.run(coroutine))
  except BaseException as exc: failure.append(exc)
 thread=threading.Thread(target=runner,name="core-adapter-startup-proof",daemon=True)
 thread.start(); thread.join(125.0)
 if thread.is_alive(): raise CoreRuntimeError("native startup chat proof exceeded its fixed deadline")
 if failure: raise CoreRuntimeError("native startup chat proof failed") from None
 if len(result)!=1: raise CoreRuntimeError("native startup chat proof returned no bounded result")
 return result[0]

def verify_starting_lifecycle_observer_custody(custody):
 """Revalidate the one active Root-CLI observer against its guarded new peer."""
 try:
  held=_STARTING_LIFECYCLE_OBSERVER_ACTIVE.get(id(custody))
  if (type(custody) is not StartingLifecycleObserverCustody
      or custody._seal is not _STARTING_LIFECYCLE_OBSERVER_SEAL
      or held is None or held.get("object") is not custody
      or os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
      or time.monotonic()>=custody.expires_monotonic
      or _ADAPTER_STARTUP_COHORT_CONTEXT.get() is not held.get("startup_context")):
   return False
  context=held["startup_context"]; cohort=custody.cohort
  from .remote.core_native_observer import RootLifecycleStartupCohort
  if (type(cohort) is not RootLifecycleStartupCohort or not cohort.is_root_selected()
      or custody.new_read is not context.get("new_read")
      or custody.peer_pid!=context.get("pid")
      or custody.peer_start_ticks!=context.get("evidence",{}).get("start_ticks")
      or custody.boot_id!=context.get("evidence",{}).get("boot_id")
      or custody.invocation_id!=context.get("evidence",{}).get("invocation_id")
      or not _validate_guarded_new_read(custody.new_read)):
   return False
  poller=select.poll(); poller.register(custody.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
  evidence,identity=_adapter_process_identity(Path(context["cohort"]["new_source"]),
   context["adapter"],context["core"],context["pid"])
  if (poller.poll(0) or identity!=context["identity"]
      or evidence["start_ticks"]!=custody.peer_start_ticks
      or evidence["boot_id"]!=custody.boot_id
      or evidence["invocation_id"]!=custody.invocation_id):
   return False
  from .remote import core_gateway_inspector as inspector
  listener_inode=inspector._core_listener_inode(context["pid"])
  generation_payload=(f"{custody.invocation_id}\0{custody.peer_pid}\0"
   f"{custody.peer_start_ticks}\0{listener_inode}\0{context['core']}").encode("ascii")
  current_core_generation=hashlib.sha256(
   b"hermes-jarvis-core-generation-v1\0"+generation_payload).hexdigest()
  status_fields={line.split(":",1)[0]:line.split(":",1)[1].split()
   for line in (Path("/proc")/str(custody.peer_pid)/"status").read_text().splitlines()
   if ":" in line}
  uids=status_fields.get("Uid",()); gids=status_fields.get("Gid",())
  if (len(uids)<2 or len(gids)<2 or int(uids[1])!=custody.peer_uid
      or int(gids[1])!=custody.peer_gid or custody.peer_uid!=1000 or custody.peer_gid!=1000
      or current_core_generation!=cohort.core_generation):
   return False
  primary_raw,primary_record,soul,signature=_initial_primary_record_and_soul()
  if (primary_raw!=context.get("primary") or primary_record is None
      or primary_record.get("state")!="adopted"
      or hashlib.sha256(soul).hexdigest()!=context.get("primary_source")
      or tuple(signature)!=tuple(primary_record.get("result_soul_signature",()))
      or primary_record.get("native_effective_prompt_sha256")!=context.get("soul")):
   return False
  current_resources=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
   mode=0o600,maximum=16*1024)
  if (current_resources!=context.get("resources_raw")
      or hashlib.sha256(current_resources).hexdigest()!=cohort.rs_sha256):
   return False
  fields={
   "transaction_id":context["cohort"]["cohort_transaction_id"],
   "starting_journal_sha256":hashlib.sha256(context["journal_raw"]).hexdigest(),
   "cohort_sha256":hashlib.sha256(context["cohort_raw"]).hexdigest(),
   "old_adapter_generation":context["cohort"]["old_adapter_generation"],
   "new_adapter_generation":context["adapter"],"core_source_generation":context["core"],
   "generation_a1_sha256":context["artifact"],
   "js_sha256":hashlib.sha256(context["journal_raw"]).hexdigest(),
   "rs_sha256":hashlib.sha256(context["resources_raw"]).hexdigest(),
   "u1_sha256":hashlib.sha256(context["unit"]).hexdigest(),
   "l1_sha256":hashlib.sha256(context["launcher"]).hexdigest(),
   "primary_source_sha256":context["primary_source"],"active_soul_sha256":context["soul"],
   "native_inventory_sha256":context["resources"]["loaded_skill_inventory_sha256"],
   "peer_pid":context["pid"],"peer_uid":custody.peer_uid,"peer_gid":custody.peer_gid,
   "peer_start_ticks":custody.peer_start_ticks,"boot_id":custody.boot_id,
   "invocation_id":custody.invocation_id,
  }
  return all(getattr(cohort,key,None)==value for key,value in fields.items())
 except Exception:
  return False

def _root_codex_account_fingerprint():
 """Read only the selected owner's Codex account digest in its pinned PM runtime."""
 if os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get():
  raise CoreRuntimeError("Root Codex account readback requires the locked source update")
 context=_ADAPTER_STARTUP_COHORT_CONTEXT.get()
 if (type(context) is not dict or context.get("cohort",{}).get("phase")!="source-starting"
     or context.get("adapter")!=context.get("cohort",{}).get("new_adapter_generation")):
  raise CoreRuntimeError("Root Codex account readback has no selected starting cohort")
 _validate_adapter_source_path()
 if _core_source_generation()!=context.get("core"):
  raise CoreRuntimeError("fixed Hermes source changed before the account readback")
 from .remote import core_gateway_inspector as inspector
 if inspector._current_native_adapter_generation(deadline=time.monotonic()+8.0)!=context["adapter"]:
  raise CoreRuntimeError("fixed installer source changed before the account readback")
 runuser=_validated_executable(RUNUSER,{ROOT_UID})
 interpreter=_validated_executable(PYTHON,{1000})
 if runuser!=RUNUSER or interpreter!=PYTHON:
  raise CoreRuntimeError("fixed Hermes account-readback executables differ")
 code=("from hermes_cli.auth_codex import resolve_codex_runtime_credentials; "
  "from hermes_installer.remote.core_native_observer import _codex_account_fingerprint; "
  "print(_codex_account_fingerprint(lambda: resolve_codex_runtime_credentials(read_only=True)))")
 argv=[str(runuser),"-u","admin","--",str(interpreter),"-P","-c",code]
 env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":str(HOME),
  "HERMES_HOME":str(HERMES_HOME),"LANG":"C.UTF-8",
  "PYTHONPATH":f"{SOURCE}:{ADAPTER_SOURCE}","PYTHONNOUSERSITE":"1",
  "PYTHONDONTWRITEBYTECODE":"1"}
 try:
  result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
   stderr=subprocess.PIPE,timeout=15,env=env,check=False,close_fds=True,cwd=WORKSPACE)
 except (OSError,subprocess.TimeoutExpired,ValueError):
  raise CoreRuntimeError("fixed Hermes Codex account readback is unavailable") from None
 output=result.stdout
 if (result.returncode!=0 or not isinstance(output,bytes) or len(output)!=65
     or not output.endswith(b"\n")
     or re.fullmatch(rb"[0-9a-f]{64}\n",output) is None):
  raise CoreRuntimeError("fixed Hermes Codex account readback did not return one bounded digest")
 return output[:-1].decode("ascii")

@contextmanager
def _starting_lifecycle_observer():
 """Run the exact purpose-only Root observer for this guarded starting tuple."""
 context=_ADAPTER_STARTUP_COHORT_CONTEXT.get()
 if (os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
     or type(context) is not dict or context.get("cohort",{}).get("phase")!="source-starting"
     or not _validate_guarded_new_read(context.get("new_read"))):
  raise CoreRuntimeError("starting lifecycle observer requires the guarded new cohort")
 pid=context["pid"]; pidfd=context["pidfd"]
 poller=select.poll(); poller.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 if poller.poll(0): raise CoreRuntimeError("starting lifecycle peer PIDFD has exited")
 from .remote import core_gateway_inspector as inspector
 from .remote.core_native_observer import make_root_lifecycle_startup_cohort
 from .remote.core_client import CoreRpcClient
 listener_inode=inspector._core_listener_inode(pid)
 if type(listener_inode) is not int or listener_inode<1:
  raise CoreRuntimeError("starting lifecycle peer listener inode is unavailable")
 invocation=context["evidence"]["invocation_id"]
 start_ticks=context["evidence"]["start_ticks"]
 peer_status={line.split(":",1)[0]:line.split(":",1)[1].split()
  for line in (Path("/proc")/str(pid)/"status").read_text().splitlines() if ":" in line}
 uids=peer_status.get("Uid",()); gids=peer_status.get("Gid",())
 if len(uids)<2 or len(gids)<2 or int(uids[1])!=1000 or int(gids[1])!=1000:
  raise CoreRuntimeError("starting lifecycle peer credentials differ from the selected Core owner")
 generation_payload=(f"{invocation}\0{pid}\0{start_ticks}\0{listener_inode}\0{context['core']}").encode("ascii")
 core_generation=hashlib.sha256(b"hermes-jarvis-core-generation-v1\0"+generation_payload).hexdigest()
 status=_run_root_coro(CoreRpcClient().get_model_provider_status())
 if (type(status) is not dict or status.get("provider_hint")!="openai-codex"
     or status.get("codex_credential_configured") is not True
     or not isinstance(status.get("model"),str)):
  raise CoreRuntimeError("new Core does not expose the selected Codex subscription route")
 account=_root_codex_account_fingerprint()
 if not re.fullmatch(r"[0-9a-f]{64}",account):
  raise CoreRuntimeError("current Codex account fingerprint is unavailable")
 now=time.monotonic(); deadline=min(now+110.0,float(context["cohort"].get("deadline_monotonic",now+110.0)))
 cohort=make_root_lifecycle_startup_cohort(
  transaction_id=context["cohort"]["cohort_transaction_id"],
  starting_journal_sha256=hashlib.sha256(context["journal_raw"]).hexdigest(),
  cohort_sha256=hashlib.sha256(context["cohort_raw"]).hexdigest(),core_generation=core_generation,
  old_adapter_generation=context["cohort"]["old_adapter_generation"],
  new_adapter_generation=context["adapter"],core_source_generation=context["core"],
  generation_a1_sha256=context["artifact"],
  js_sha256=hashlib.sha256(context["journal_raw"]).hexdigest(),
  rs_sha256=hashlib.sha256(context["resources_raw"]).hexdigest(),
  u1_sha256=hashlib.sha256(context["unit"]).hexdigest(),
  l1_sha256=hashlib.sha256(context["launcher"]).hexdigest(),
  primary_source_sha256=context["primary_source"],active_soul_sha256=context["soul"],
  native_inventory_sha256=context["resources"]["loaded_skill_inventory_sha256"],
  peer_pid=pid,peer_uid=int(uids[1]),peer_gid=int(gids[1]),peer_start_ticks=start_ticks,
  boot_id=context["evidence"]["boot_id"],invocation_id=invocation,
  provider="openai-codex",api_mode="codex_responses",
  base_url="https://chatgpt.com/backend-api/codex",model=status["model"],
  account_fingerprint=account,issued_monotonic=now,deadline_monotonic=deadline)
 from .remote.core_native_observer import RootLifecycleNativeObservationRegistry, RootLifecycleNativeObservationServer
 custody=StartingLifecycleObserverCustody(cohort=cohort,peer_pid=pid,peer_uid=int(uids[1]),peer_gid=int(gids[1]),
  peer_start_ticks=start_ticks,boot_id=context["evidence"]["boot_id"],invocation_id=invocation,
  pidfd=pidfd,expires_monotonic=deadline,new_read=context["new_read"],
  _seal=_STARTING_LIFECYCLE_OBSERVER_SEAL)
 _STARTING_LIFECYCLE_OBSERVER_ACTIVE[id(custody)]={"object":custody,"startup_context":context}
 registry=None; server=None
 try:
  if not verify_starting_lifecycle_observer_custody(custody):
   raise CoreRuntimeError("starting lifecycle observer custody is stale")
  registry=RootLifecycleNativeObservationRegistry.from_starting_custody(custody)
  server=RootLifecycleNativeObservationServer(registry)
  server.start()
  if server.wait_ready(timeout=3.0) is not True:
   raise CoreRuntimeError("Root lifecycle observer socket did not become ready")
  yield _StartingLifecycleObserverSession(custody=custody,registry=registry,rpc=CoreRpcClient())
 finally:
  try:
   if server is not None: server.close()
   elif registry is not None: registry.close()
  finally:
   _STARTING_LIFECYCLE_OBSERVER_ACTIVE.pop(id(custody),None)

def _prove_new_cohort_startup_chat():
 """Require one real native, no-tools Codex completion for the guarded new peer."""
 context=_ADAPTER_STARTUP_COHORT_CONTEXT.get()
 if (os.geteuid()!=ROOT_UID or not _ADAPTER_UPDATE_LOCK_HELD.get()
     or type(context) is not dict or context.get("cohort",{}).get("phase")!="source-starting"):
  raise CoreRuntimeError("guarded new-source startup proof context is unavailable")
 import select
 poller=select.poll(); poller.register(context["pidfd"],select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
 if (poller.poll(0) or not _validate_guarded_new_read(context.get("new_read"))
     or _adapter_process_identity(ADAPTER_SOURCE,context["adapter"],context["core"],context["pid"])[1]
        !=context["identity"]):
  raise CoreRuntimeError("guarded startup peer changed before lifecycle chat enrollment")
 from .remote.core_native_observer import (
  CoreVerifiedLifecycleStartupCompletion, make_root_lifecycle_startup_cohort,
 )
 with _starting_lifecycle_observer() as observer:
  custody=observer.custody; registry=observer.registry; rpc=observer.rpc
  cohort=custody.cohort
  handle=registry.enroll_lifecycle_startup_probe(cohort=cohort)
  wire=_run_root_coro(rpc.lifecycle_startup_probe(handle))
  if (type(wire) is not dict
      or set(wire)!={"schema","probe_handle","completion_handle","status","response_sha256"}
      or type(wire.get("schema")) is not int or wire.get("schema")!=1
      or wire.get("probe_handle")!=handle or wire.get("status")!="completed"):
   raise CoreRuntimeError("new Core lifecycle startup response is not the exact completed proof")
  proof=registry.consume_lifecycle_startup_completion(
   probe_handle=wire["probe_handle"],completion_handle=wire["completion_handle"],
   native_response_sha256=wire["response_sha256"])
  expected=("transaction_id","starting_journal_sha256","cohort_sha256","core_generation",
   "old_adapter_generation","new_adapter_generation","core_source_generation",
   "generation_a1_sha256","js_sha256","rs_sha256","u1_sha256","l1_sha256",
   "primary_source_sha256","active_soul_sha256","native_inventory_sha256","peer_pid",
   "peer_uid","peer_gid","peer_start_ticks","boot_id","invocation_id","provider",
   "api_mode","base_url","model","account_fingerprint")
  if (type(proof) is not CoreVerifiedLifecycleStartupCompletion
      or proof.is_root_verified() is not True
      or any(getattr(proof,key,None)!=getattr(cohort,key,None) for key in expected)
      or not verify_starting_lifecycle_observer_custody(custody)):
   raise CoreRuntimeError("new Core lifecycle completion does not join its selected source cohort")
  account=_root_codex_account_fingerprint()
  status=_run_root_coro(rpc.get_model_provider_status())
  if (account!=cohort.account_fingerprint or type(status) is not dict
      or status.get("provider_hint")!=cohort.provider
      or status.get("codex_credential_configured") is not True
      or status.get("model")!=cohort.model
      or time.monotonic()>=cohort.deadline_monotonic
      or poller.poll(0) or _adapter_process_identity(ADAPTER_SOURCE,context["adapter"],
       context["core"],context["pid"])[1]!=context["identity"]):
   raise CoreRuntimeError("new Core lifecycle completion is stale against route, account, or peer")
  return proof

def _recover_interrupted_adapter_update():
 # The cohesive M1 cohort keeps the original ownership journal byte-identical
 # until all owner bindings are rebound. Therefore its phase, not a synthetic
 # `preparing` value in that journal, is the recovery authority.
 try:
  cohort,cohort_raw=_read_adapter_update_cohort(allow_absent=True)
 except CoreRuntimeError:
  raise
 if cohort is not None and cohort["phase"]!="committed":
  reference=_adapter_update_backup_reference(cohort)
  prior_source=Path(cohort["old_source"]); target=Path(cohort["new_source"])
  _validate_adapter_generation_path(prior_source); _validate_adapter_generation_path(target)
  try:
   _restore_adapter_update_backup(reference,allowed_sources=(prior_source,target))
  except Exception:
   raise CoreRuntimeError("interrupted adapter cohort retained its protected recovery backup") from None
  return
 if not JOURNAL.is_file() or JOURNAL.is_symlink(): return
 raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 try: record=json.loads(raw)
 except (ValueError,TypeError): return
 if type(record) is not dict or record.get("adapter_update_state") not in {"preparing","starting"}: return
 target=Path(record.get("adapter_update_target_source",""))
 prior_source=Path(record.get("adapter_update_previous_source",""))
 reference=record.get("adapter_update_backup")
 _validate_adapter_generation_path(target); _validate_adapter_generation_path(prior_source)
 try:
  _restore_adapter_update_backup(reference,allowed_sources=(prior_source,target))
 except Exception:
  raise CoreRuntimeError("interrupted adapter update retained its protected recovery backup") from None

def _adapter_update_backup_reference(cohort):
 """Resolve only the fixed old-generation backup named by the protected cohort."""
 if type(cohort) is not dict:
  raise CoreRuntimeError("adapter update recovery cohort is unavailable")
 generation=cohort.get("old_adapter_generation")
 if not isinstance(generation,str) or re.fullmatch(r"[0-9a-f]{64}",generation) is None:
  raise CoreRuntimeError("adapter update recovery generation is invalid")
 backup=ADAPTER_UPDATE_BACKUPS/generation
 raw=_projection_file(backup/"manifest.json",owner=ROOT_UID,group=ROOT_UID,
                      mode=0o600,maximum=4096)
 try:
  manifest=json.loads(raw)
 except (ValueError,TypeError):
  raise CoreRuntimeError("adapter update recovery manifest is malformed") from None
 expected={"journal.json":cohort["old_journal_sha256"],
  "unit":cohort["old_unit_sha256"],"launcher":cohort["old_launcher_sha256"],
  "resources-record.json":cohort["old_resources_record_sha256"]}
 transition=cohort.get("native_plugin_transition")
 if transition is not None:
  _validate_native_plugin_transition_row(transition,cohort)
  if transition.get("plugin_selection_sha256")!=json.loads(
      _projection_file(backup/"journal.json",owner=ROOT_UID,group=ROOT_UID,
       mode=0o600,maximum=64*1024)).get("plugin_selection_sha256"):
   raise CoreRuntimeError("native plugin transition selection differs from prior journal")
  for member,backup_name in _NATIVE_PLUGIN_BACKUP_NAMES.items():
   expected[backup_name]=transition["old_members"][member]
 elif set(manifest)!={"journal.json","unit","launcher","plugin-selection.json",
   "resources-record.json","overlay-record.json","primary-record.json",
   "obsidian-registration.json","cohort.json"}:
  raise CoreRuntimeError("native plugin backup exists without a cohort transition")
 if (type(manifest) is not dict
     or set(manifest)!=set(expected) | {"plugin-selection.json","overlay-record.json",
       "primary-record.json","obsidian-registration.json","cohort.json"}
     or any(manifest.get(name)!=digest for name,digest in expected.items())):
  raise CoreRuntimeError("adapter update recovery backup differs from its cohort")
 return {"path":str(backup),"source_generation":generation,"files":manifest}

def _retained_committed_adapter_cohort_sha256(cohort,raw):
 """Resolve the sole writer-defined committed-to-rollback cohort transform."""
 if type(cohort) is not dict or not isinstance(raw,bytes): return None
 try:
  if raw!=_canonical_json(cohort): return None
 except (TypeError,ValueError):
  return None
 if cohort.get("phase")=="committed":
  return hashlib.sha256(raw).hexdigest()
 if cohort.get("phase")!="rolling-back":
  return hashlib.sha256(raw).hexdigest()
 rolling_reconstruction=cohort.get("reconstruction")
 if (type(rolling_reconstruction) is not dict
     or rolling_reconstruction.get("phase")!="rolling-back"
     or cohort.get("reconstruction_sha256")
        !=hashlib.sha256(_canonical_json(rolling_reconstruction)).hexdigest()):
  return None
 committed=dict(cohort)
 committed["phase"]="committed"
 reconstruction=dict(rolling_reconstruction)
 reconstruction["phase"]="committed"
 committed["reconstruction"]=reconstruction
 committed["reconstruction_sha256"]=hashlib.sha256(_canonical_json(reconstruction)).hexdigest()
 initial=committed.get("initial_primary_transition")
 if initial is not None:
  if type(initial) is not dict or initial.get("state")!="rolling-back": return None
  initial=dict(initial); initial["state"]="adopted"
  committed["initial_primary_transition"]=initial
 try:
  committed_raw=_canonical_json(committed)
 except (TypeError,ValueError):
  return None
 return hashlib.sha256(committed_raw).hexdigest()

def restore_owned_core_adapter_update():
 """Restore only the current committed update retained by the ingress cohort."""
 if os.geteuid()!=ROOT_UID or not Path("/proc").is_dir():
  raise CoreRuntimeError("owned adapter update restore requires the Root Linux actor")
 with _adapter_update_lock():
  raw=_projection_file(NATIVE_ADOPTION_INGRESS_BACKUP,owner=ROOT_UID,
   group=ROOT_UID,mode=0o600,maximum=128*1024)
  def unique(pairs):
   value={}
   for key,item in pairs:
    if key in value: raise ValueError
    value[key]=item
   return value
  try: ingress=json.loads(raw,object_pairs_hook=unique)
  except (ValueError,TypeError):
   raise CoreRuntimeError("retained ingress recovery journal is malformed") from None
  fields={"schema","purpose","old_core_journal_sha256","old_core_adapter_source",
   "old_core_adapter_generation","old_core_source_generation",
   "old_inspector_process_identity_sha256","old_observer_state","old_observer_device",
   "old_observer_inode","core_update_backup_reference",
   "core_update_cohort_transaction_id","core_update_cohort_sha256"}
  refresh=ingress.get("adapter_refresh") if type(ingress) is dict else None
  if (type(ingress) is not dict or ingress.get("schema")!=1
      or ingress.get("state")!="recovery-required"
      or type(refresh) is not dict or set(refresh)!=fields
      or refresh.get("schema")!=1 or refresh.get("purpose")!="adapter-refresh"):
   raise CoreRuntimeError("no exact recovery-required native adapter refresh is retained")
  for key in ("old_core_journal_sha256","old_core_adapter_generation",
              "old_core_source_generation","old_inspector_process_identity_sha256"):
   if not isinstance(refresh.get(key),str) or re.fullmatch(r"[0-9a-f]{64}",refresh[key]) is None:
    raise CoreRuntimeError("retained adapter refresh digest is malformed")
  if (not isinstance(refresh.get("old_core_adapter_source"),str)
      or not Path(refresh["old_core_adapter_source"]).is_absolute()
      or refresh.get("old_observer_state") not in {"verified-owned","absent"}
      or (refresh["old_observer_state"]=="verified-owned"
       and (type(refresh.get("old_observer_device")) is not int
        or type(refresh.get("old_observer_inode")) is not int
        or refresh["old_observer_device"]<0 or refresh["old_observer_inode"]<1))
      or (refresh["old_observer_state"]=="absent"
       and (refresh.get("old_observer_device") is not None
        or refresh.get("old_observer_inode") is not None))):
   raise CoreRuntimeError("retained old Core or observer identity is malformed")

  cohort,cohort_raw=_read_adapter_update_cohort()
  candidate=ingress.get("candidate_sha")
  phase=cohort.get("phase")
  if (phase not in _ADAPTER_COHORT_PHASES
      or not isinstance(candidate,str) or re.fullmatch(r"[0-9a-f]{40}",candidate) is None
      or cohort.get("new_source")!=str(ADAPTER_SOURCE)
      or Path(cohort["new_source"]).parent.name!="hermes-installer-core-"+candidate[:9]):
   raise CoreRuntimeError("current Core cohort is not the retained native recovery candidate")
  provenance_raw=_projection_file(ADAPTER_SOURCE.parent/".source-provenance.json",
   owner=ROOT_UID,group=ROOT_UID,mode=0o444,maximum=4096)
  try: provenance=json.loads(provenance_raw,object_pairs_hook=unique)
  except (ValueError,TypeError):
   raise CoreRuntimeError("current candidate source provenance is malformed") from None
  if (type(provenance) is not dict
      or set(provenance)!={"schema","source_commit","archive_sha256"}
      or provenance.get("schema")!=1 or provenance.get("source_commit")!=candidate
      or not isinstance(provenance.get("archive_sha256"),str)
      or re.fullmatch(r"[0-9a-f]{64}",provenance["archive_sha256"]) is None
      or provenance_raw!=_canonical_json(provenance)):
   raise CoreRuntimeError("current candidate source provenance differs from the retained ingress candidate")
  reference=_adapter_update_backup_reference(cohort)
  prior,contents=_read_adapter_update_backup(reference)
  old_journal=contents["journal.json"]
  if (hashlib.sha256(old_journal).hexdigest()!=refresh["old_core_journal_sha256"]
      or prior.get("service")!=SERVICE or prior.get("adapter_migration_state")!="active"
      or prior.get("adapter_source")!=refresh["old_core_adapter_source"]
      or prior.get("adapter_generation")!=refresh["old_core_adapter_generation"]
      or prior.get("core_source_generation")!=refresh["old_core_source_generation"]
      or cohort.get("old_journal_sha256")!=refresh["old_core_journal_sha256"]
      or cohort.get("old_source")!=refresh["old_core_adapter_source"]
      or cohort.get("old_adapter_generation")!=refresh["old_core_adapter_generation"]
      or cohort.get("old_core_source_generation")!=refresh["old_core_source_generation"]):
   raise CoreRuntimeError("retained old Core tuple differs from the exact protected update backup")
  transaction=refresh.get("core_update_cohort_transaction_id")
  cohort_sha=refresh.get("core_update_cohort_sha256")
  retained_reference=refresh.get("core_update_backup_reference")
  joins=(retained_reference,transaction,cohort_sha)
  retained_cohort_sha=_retained_committed_adapter_cohort_sha256(cohort,cohort_raw)
  if all(value is None for value in joins):
   # Core may advance immediately before the adopter persists its three
   # joins. The current protected cohort and its exact retained old backup
   # must still independently join the ingress snapshot.
   pass
  elif (any(value is None for value in joins)
        or retained_reference!=reference
        or transaction!=cohort["cohort_transaction_id"]
        or not isinstance(cohort_sha,str)
        or re.fullmatch(r"[0-9a-f]{64}",cohort_sha) is None
        or cohort_sha!=retained_cohort_sha):
   raise CoreRuntimeError("retained adapter refresh does not join the current protected Core update")

  for unit in ("hermes-jarvis-core-gateway.service","hermes-jarvis-mvp-tunnel.service"):
   if _run(["systemctl","is-active",unit],False).stdout.strip()!="inactive":
    raise CoreRuntimeError("public ingress must remain stopped during Core update recovery")
  if phase!="committed":
   # The normal qualification runner rejects these in-flight phases before
   # it can reach recovery. Reuse its exact journaled rollback under the same
   # lock, after independently joining the retained ingress row to the
   # protected candidate and old backup above.
   _recover_interrupted_adapter_update()
   restored=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
   if restored!=old_journal:
    raise CoreRuntimeError("interrupted Core cohort did not restore the exact prior journal")
   prior_live,prior_live_raw,_prior_files=_read_active_adapter_runtime()
   if (prior_live_raw!=old_journal
       or prior_live.get("adapter_source")!=refresh["old_core_adapter_source"]
       or prior_live.get("adapter_generation")!=refresh["old_core_adapter_generation"]
       or prior_live.get("core_source_generation")!=refresh["old_core_source_generation"]):
    raise CoreRuntimeError("interrupted Core cohort did not restore the prior live source tuple")
   return "exact interrupted Core cohort restored to its prior adapter; ingress remains stopped"

  current, _current_raw, _files=_read_active_adapter_runtime()
  if (current.get("adapter_source")!=cohort.get("new_source")
      or current.get("adapter_generation")!=cohort.get("new_adapter_generation")
      or current.get("core_source_generation")!=cohort.get("new_core_source_generation")
      or current.get("adapter_update_state")!="active"
      or current.get("adapter_update_backup")!=reference
      or current.get("adapter_update_previous_source")!=cohort.get("old_source")
      or current.get("adapter_update_target_source")!=cohort.get("new_source")
      or current.get("adapter_update_target_generation")!=cohort.get("new_adapter_generation")
      or current.get("adapter_update_cohort_transaction_id")!=cohort.get("cohort_transaction_id")):
   raise CoreRuntimeError("current Core journal does not bind the exact committed update cohort")
  _restore_adapter_update_backup(reference,allowed_sources=(
   Path(cohort["old_source"]),Path(cohort["new_source"])))
  restored=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
  if restored!=old_journal:
   raise CoreRuntimeError("prior adapter Core journal did not restore exactly")
  prior_live,prior_live_raw,_prior_files=_read_active_adapter_runtime()
  if (prior_live_raw!=old_journal
      or prior_live.get("adapter_source")!=refresh["old_core_adapter_source"]
      or prior_live.get("adapter_generation")!=refresh["old_core_adapter_generation"]
      or prior_live.get("core_source_generation")!=refresh["old_core_source_generation"]):
   raise CoreRuntimeError("restored prior Core process or source tuple is not current")
  return "exact prior journal-owned Core adapter and bindings restored; ingress remains stopped"

def update_owned_core_adapter():
 with _adapter_update_lock():
  return _update_owned_core_adapter_locked()

def _update_owned_core_adapter_locked():
 """Rebind one helper-only adapter generation as a single recoverable cohort."""
 if os.geteuid()!=ROOT_UID or not Path("/proc").is_dir():
  raise CoreRuntimeError("requires installed Linux root actor")
 _validate_adapter_source_path(); _recover_interrupted_adapter_update()
 record,raw_journal,old_files=_read_active_adapter_runtime()
 old_source=Path(record["adapter_source"]); old_adapter=record["adapter_generation"]
 old_core=record["core_source_generation"]
 if old_source==ADAPTER_SOURCE:
  raise CoreRuntimeError("current native adapter source is already installed")
 from .registry import manual_jarvis_skills as native
 from .remote.core_gateway_inspector import (
  CORE_NATIVE_ADAPTER_SOURCE_FILES,_current_native_adapter_generation,
  verify_staged_native_resources_plugin,
 )
 from .remote.native_plugin_bootstrap import verify_native_resources_plugin_selection
 deadline=time.monotonic()+35.0
 new_adapter=_current_native_adapter_generation(deadline=deadline)
 selection=verify_native_resources_plugin_selection()
 selection_digest=getattr(selection,"selection_sha256",None)
 old_plugin_members=_native_plugin_source_members(old_source)
 new_plugin_members=_native_plugin_source_members(ADAPTER_SOURCE)
 installed_plugin=_read_installed_native_resources_plugin_members()
 if dict(installed_plugin.members)!=old_plugin_members:
  raise CoreRuntimeError("installed native plugin pair differs from the active old source")
 expected_bundle_hashes={
  name:CORE_NATIVE_ADAPTER_SOURCE_FILES[
   "hermes_installer/components/resources_native_plugin_bundle/"+name]
  for name in _NATIVE_PLUGIN_FILES}
 if (_native_plugin_member_hashes(new_plugin_members)!=expected_bundle_hashes
     or getattr(selection,"plugin_key",None)!="hermes-installer-resources-delegation"
     or selection_digest!=record["plugin_selection_sha256"]
     or _core_source_generation()!=old_core):
  raise CoreRuntimeError("incoming adapter bundle, pinned Core source, or native selection is not verified")
 plugin_transition=None
 if old_plugin_members!=new_plugin_members:
  if (old_plugin_members["plugin.yaml"]!=new_plugin_members["plugin.yaml"]
      or old_plugin_members["__init__.py"]==new_plugin_members["__init__.py"]):
   raise CoreRuntimeError("candidate is outside the fixed manifest-stable native plugin transition")
  plugin_transition={"schema":1,"purpose":"fixed-native-resources-plugin",
   "old_adapter_generation":old_adapter,"new_adapter_generation":new_adapter,
   "plugin_selection_sha256":selection_digest,
   "old_members":_native_plugin_member_hashes(old_plugin_members),
   "new_members":_native_plugin_member_hashes(new_plugin_members)}
 staged_digest=None
 if (not re.fullmatch(r"[0-9a-f]{64}",str(new_adapter or ""))
     or not re.fullmatch(r"[0-9a-f]{64}",str(selection_digest or ""))
     or _core_source_generation()!=old_core):
  raise CoreRuntimeError("incoming adapter, pinned Core source, or native selection is not verified")
 snapshots=_snapshot_adapter_update_bindings(core_source_generation=old_core)
 resources_raw=snapshots["resources_record"]
 try: old_discovery=json.loads(resources_raw)
 except (ValueError,TypeError): raise CoreRuntimeError("current Resources receipt is malformed") from None
 if (old_discovery.get("core_ownership_sha256")!=hashlib.sha256(raw_journal).hexdigest()
     or old_discovery.get("artifact_sha256") is None
     or read_current_resources_discovery(core_source_generation=old_core).get("resources_state")!="discovered"):
  raise CoreRuntimeError("current Resources generation is not fully discovered")
 old_artifact=old_discovery["artifact_sha256"]
 old_archive=_projection_file(RESOURCES_CAS/(old_artifact+".zip"),owner=ROOT_UID,
  group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 if hashlib.sha256(old_archive).hexdigest()!=old_artifact:
  raise CoreRuntimeError("current Resources immutable CAS bytes differ")
 overlay_record,overlay_contents,overlay_raw=_read_adapter_overlay_snapshot()
 if overlay_raw is None:
  old_base=old_archive
 else:
  old_base_sha=overlay_record["base_artifact_sha256"]
  old_base=_projection_file(RESOURCES_CAS/(old_base_sha+".zip"),owner=ROOT_UID,
   group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
  if hashlib.sha256(old_base).hexdigest()!=old_base_sha:
   raise CoreRuntimeError("original owner-overlay base CAS is unavailable")
 new_base=native.build_manual_jarvis_skills_artifact()
 reconstruction=_make_adapter_update_reconstruction(old_base,new_base,old_archive,
  overlay_record,overlay_contents,overlay_raw,
  _projection_file(HERMES_HOME/"skills"/native._GENERATION/native._OWNER_FILE,
   owner=1000,group=1000,mode=0o600,maximum=2*1024*1024),resources_raw)
 new_archive=reconstruction.new_composed_archive
 old_manifest,old_generation_files,_old_helper=native._read_transition_archive(
  old_archive,old_artifact)
 new_artifact=reconstruction.new_composed_artifact_sha256
 new_manifest,new_generation_files,_new_helper=native._read_transition_archive(
  new_archive,new_artifact)
 shared_manifest,shared_tree,shared_count=native._same_materialization_digests(
  new_manifest,new_generation_files)
 if (shared_manifest!=native._same_materialization_digests(old_manifest,old_generation_files)[0]
     or shared_tree!=reconstruction.materialized_tree_sha256
     or not native.verify_same_materialization_transition(old_manifest,old_generation_files,
       new_manifest,new_generation_files)):
  raise CoreRuntimeError("composed A0→A1 pair is not an exact helper-only transition")
 new_unit=_unit(adapter_source=ADAPTER_SOURCE,cohort_gate=True,backup_generation=old_adapter)
 new_launcher=_launcher(adapter_source=ADAPTER_SOURCE)
 old_unit=old_files[UNIT]; old_launcher=old_files[LAUNCHER]
 new_unit_sha=hashlib.sha256(new_unit).hexdigest(); new_launcher_sha=hashlib.sha256(new_launcher).hexdigest()
 old_unit_sha=hashlib.sha256(old_unit).hexdigest(); old_launcher_sha=hashlib.sha256(old_launcher).hexdigest()
 old_recipe=_adapter_recipe_sha256(str(old_source),old_adapter,old_unit_sha,old_launcher_sha)
 new_recipe=_adapter_recipe_sha256(str(ADAPTER_SOURCE),new_adapter,new_unit_sha,new_launcher_sha)
 guarded_old_unit=_unit(adapter_source=old_source,cohort_gate=True,backup_generation=old_adapter)
 guarded_old_unit_sha=hashlib.sha256(guarded_old_unit).hexdigest()
 guarded_old_recipe=_adapter_recipe_sha256(str(old_source),old_adapter,
  guarded_old_unit_sha,old_launcher_sha)
 old_installed_journal=_projection_file(HERMES_HOME/"skills"/native._GENERATION/native._OWNER_FILE,
  owner=1000,group=1000,mode=0o600,maximum=2*1024*1024)
 old_custody=_hash_generation_tree(HERMES_HOME,old_manifest,old_generation_files,old_artifact)
 primary_raw=snapshots["primary_record"]
 initial_primary_transition=None
 initial_primary_prior_soul=None
 if primary_raw:
  from . import primary_prompt_manager as primary
  try:
   parsed=primary._read_record(sys.modules[__name__])
   if parsed is None or parsed.get("state")!="adopted": raise ValueError
   soul,soul_signature=primary._read_soul(sys.modules[__name__])
   prefix,separator,block=primary.split_managed_block(soul,
    owner_prefix_length=parsed["owner_prefix_length"],
    separator=bytes.fromhex(parsed["owner_separator_hex"]))
   prior_backup=primary._backup_read(sys.modules[__name__],parsed)
   if (parsed.get("core_source_generation")!=old_core or parsed.get("artifact_sha256")!=old_artifact
       or hashlib.sha256(soul).hexdigest()!=parsed.get("result_soul_sha256")
       or hashlib.sha256(prior_backup).hexdigest()!=parsed.get("owner_backup_name")):
    raise ValueError
   primary_values={"primary_record_sha256":hashlib.sha256(primary_raw).hexdigest(),
    "soul_sha256":hashlib.sha256(soul).hexdigest(),"soul_signature":tuple(soul_signature),
    "owner_prefix_sha256":hashlib.sha256(prefix).hexdigest(),"owner_prefix_length":len(prefix),
    "owner_separator_hex":separator.hex(),"managed_block_sha256":hashlib.sha256(block).hexdigest(),
    "prior_backup_sha256":hashlib.sha256(prior_backup).hexdigest(),
    "native_effective_prompt_sha256":parsed.get("native_effective_prompt_sha256")}
  except Exception:
   raise CoreRuntimeError("existing primary adoption or its exact owner bytes are not eligible") from None
 else:
  from . import primary_prompt_manager as primary
  from .registry.primary_prompt import append_managed_block,render_managed_block
  try:
   if PRIMARY_PROMPT_JOURNAL.exists() or PRIMARY_PROMPT_JOURNAL.is_symlink(): raise ValueError
   initial_primary_prior_soul,initial_primary_signature=primary._read_soul(sys.modules[__name__])
   source_prompt=new_generation_files.get("registry/profiles/hermes/SOUL.md")
   if not isinstance(source_prompt,bytes): raise ValueError
   managed_block=render_managed_block(source_prompt)
   desired_soul,owner_separator=append_managed_block(initial_primary_prior_soul,managed_block)
   initial_primary_transition={
    "schema":1,"purpose":"initial-primary-adoption","state":"pending",
    "prior_record_state":"absent",
    "prior_soul_sha256":hashlib.sha256(initial_primary_prior_soul).hexdigest(),
    "prior_soul_signature":list(initial_primary_signature),
    "source_prompt_sha256":hashlib.sha256(source_prompt).hexdigest(),
    "managed_block_sha256":hashlib.sha256(managed_block).hexdigest(),
    "desired_soul_sha256":hashlib.sha256(desired_soul).hexdigest(),
    "owner_separator_hex":owner_separator.hex(),"owner_backup_sha256":None,
    "preparing_record_sha256":None,"writing_record_sha256":None,
    "adopted_record_sha256":None,
    "before_resources_record_sha256":hashlib.sha256(resources_raw).hexdigest(),
    "after_resources_record_sha256":None,
   }
  except Exception:
   raise CoreRuntimeError("initial primary adoption inputs are not exact or unambiguous") from None
  primary_values={"primary_record_sha256":_ABSENT_DIGEST,"soul_sha256":_ABSENT_DIGEST,
   "soul_signature":(),"owner_prefix_sha256":_ABSENT_DIGEST,"owner_prefix_length":0,
   "owner_separator_hex":"","managed_block_sha256":_ABSENT_DIGEST,"prior_backup_sha256":_ABSENT_DIGEST}
 if snapshots["obsidian_registration_state"]=="registered":
  obsidian_state="registered"; obsidian_sha=snapshots["obsidian_registration_sha256"]
 else: obsidian_state="absent"; obsidian_sha=_ABSENT_DIGEST
 old_pidfd,old_pid,old_process,old_process_sha=_capture_adapter_service_process(
  old_source,old_adapter,old_core)
 native_plugin_state={"old_source":str(old_source),"new_source":str(ADAPTER_SOURCE),
  "old_adapter_generation":old_adapter,"new_adapter_generation":new_adapter,
  "old_core_source_generation":old_core,"plugin_selection_sha256":selection_digest,
  "old_members":dict(old_plugin_members),"new_members":dict(new_plugin_members),
  "old_signatures":dict(installed_plugin.signatures),"old_pidfd":old_pidfd,
  "cohort_raw":None}
 cohort_id=secrets.token_hex(16)
 backup_reference=None; prepared=None; new_pidfd=None
 state={"phase":"prepared","journal_raw":raw_journal,"resources_raw":resources_raw,
  "primary_raw":primary_raw or None,"process_identity":old_process_sha,"pid":old_pid,
  "old_pidfd":old_pidfd,"source":str(old_source),"adapter":old_adapter,"core":old_core,
  "soul_sha256":primary_values["soul_sha256"] if primary_values["soul_sha256"]!=_ABSENT_DIGEST
    else hashlib.sha256(initial_primary_prior_soul).hexdigest() if initial_primary_prior_soul is not None
    else _ABSENT_DIGEST,
  "soul_signature":primary_values["soul_signature"] if primary_values["primary_record_sha256"]!=_ABSENT_DIGEST
    else tuple(initial_primary_transition["prior_soul_signature"]) if initial_primary_transition is not None
    else (),
 "overlay_raw":overlay_raw,"registration_raw":snapshots["obsidian_registration"] or None}
 native_plugin_state_token=_NATIVE_PLUGIN_TRANSITION_STATE.set(native_plugin_state)
 try:
  if plugin_transition is not None:
   _run_native_plugin_transition("prepare")
  backup_reference=_save_adapter_update_backup(record,raw_journal,old_files,selection_digest,
   resources_record=resources_raw,overlay_record=overlay_raw or b"",
   primary_record=primary_raw or b"",obsidian_registration=snapshots["obsidian_registration"],
   prior_cohort=snapshots["prior_cohort"],
   native_plugin_members=old_plugin_members if plugin_transition is not None else None)
  cohort={"schema":1,"purpose":_ADAPTER_COHORT_PURPOSE,"cohort_transaction_id":cohort_id,
   "owner_uid":1000,"home_role":"jarvis-primary-home","phase":"prepared",
   "old_source":str(old_source),"new_source":str(ADAPTER_SOURCE),
   "old_adapter_generation":old_adapter,"new_adapter_generation":new_adapter,
   "old_core_source_generation":old_core,"new_core_source_generation":old_core,
   "old_source_recipe_sha256":old_recipe,"new_source_recipe_sha256":new_recipe,
   "old_unit_sha256":old_unit_sha,"old_launcher_sha256":old_launcher_sha,
   "new_unit_sha256":new_unit_sha,"new_launcher_sha256":new_launcher_sha,
   "guarded_old_unit_sha256":guarded_old_unit_sha,"guarded_old_recipe_sha256":guarded_old_recipe,
   "old_process_identity_sha256":old_process_sha,"old_journal_sha256":hashlib.sha256(raw_journal).hexdigest(),
   "new_journal_sha256":None,"old_resources_record_sha256":hashlib.sha256(resources_raw).hexdigest(),
   "pre_switch_resources_record_sha256":None,"starting_journal_sha256":None,
   "starting_resources_record_sha256":None,"new_resources_record_sha256":None,
   "old_artifact_sha256":old_artifact,"new_artifact_sha256":new_artifact,
   "owner_generation_backup_name":".jarvis-resources-skills-helper-transition-"+cohort_id,
   "primary_record_sha256":primary_values["primary_record_sha256"],
   "obsidian_registration_state":obsidian_state,
   "obsidian_registration_sha256":obsidian_sha,
   "obsidian_vault_tree_sha256":snapshots["obsidian_vault_tree_sha256"],
   "initial_primary_transition":initial_primary_transition,
   "native_plugin_transition":plugin_transition,
   "reconstruction":None,"reconstruction_sha256":None}
  reconstruction_row=_adapter_update_reconstruction_row(reconstruction,
   cohort_id=cohort_id,phase="prepared",old_core=old_core,new_core=old_core,
   old_recipe=old_recipe,new_recipe=new_recipe,
   old_marker=hashlib.sha256(old_installed_journal).hexdigest(),old_discovery=hashlib.sha256(resources_raw).hexdigest())
  cohort["reconstruction"]=reconstruction_row
  cohort["reconstruction_sha256"]=hashlib.sha256(_canonical_json(reconstruction_row)).hexdigest()
  cohort_raw=_write_adapter_update_cohort(cohort,expected_raw=snapshots["prior_cohort"] or None)
  _atomic_replace(UNIT,guarded_old_unit,0o644,ROOT_UID,ROOT_UID)
  _run(["systemctl","daemon-reload"])
  if (_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)!=guarded_old_unit
      or not _owned_unit_loaded()
      or _projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)!=raw_journal):
   raise CoreRuntimeError("deny-by-default old-source gate did not preserve J0")
  state["cohort"]=cohort; state["cohort_raw"]=cohort_raw
  native_plugin_state["cohort_raw"]=cohort_raw
  def current_check(value,purpose):
   try:
    if (not _ADAPTER_UPDATE_LOCK_HELD.get() or time.monotonic()>=value.expires_monotonic
        or state.get("phase") not in {"prepared","resources-rebound"}): return False
    current,current_raw=_read_adapter_update_cohort()
    unit_raw=_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)
    journal_now=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
    resources_now=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
    primary_now=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,group=ROOT_UID,
     mode=0o600,maximum=64*1024) if PRIMARY_PROMPT_JOURNAL.exists() else None
    if (current["cohort_transaction_id"]!=cohort_id or current["phase"]!=state["phase"]
        or hashlib.sha256(current_raw).hexdigest()!=hashlib.sha256(state["cohort_raw"]).hexdigest()
        or journal_now!=state["journal_raw"] or resources_now!=state["resources_raw"]
        or primary_now!=state["primary_raw"] or unit_raw!=guarded_old_unit
        or not _validate_guarded_old_read(state.get("old_read"))): return False
    _overlay_record,_overlay_contents,overlay_now=_read_adapter_overlay_snapshot()
    if overlay_now!=state["overlay_raw"]: return False
    from . import primary_prompt_manager as primary
    soul_now,soul_signature_now=primary._read_soul(sys.modules[__name__])
    if (hashlib.sha256(soul_now).hexdigest()!=state["soul_sha256"]
        or (state["soul_signature"] and tuple(soul_signature_now)!=state["soul_signature"])):
     return False
    from .remote.core_gateway_inspector import _current_native_adapter_generation
    if (_current_native_adapter_generation(deadline=time.monotonic()+35.0)!=new_adapter
        or _core_source_generation()!=old_core
        or _native_plugin_source_members(old_source)!=old_plugin_members
        or _native_plugin_source_members(ADAPTER_SOURCE)!=new_plugin_members): return False
    if dict(_read_installed_native_resources_plugin_members().members)!=old_plugin_members: return False
    if current["phase"]=="resources-rebound" and state["phase"]!="resources-rebound": return False
    return True
   except Exception: return False
  old_read=_issue_guarded_old_read(cohort=cohort,cohort_raw=cohort_raw,record=record,
   journal_raw=raw_journal,old_unit=old_unit,old_launcher=old_launcher,pidfd=old_pidfd,
   pid=old_pid,process_identity_sha256=old_process_sha)
  state["old_read"]=old_read
  old_base_sha=reconstruction.old_base_artifact_sha256
  new_base_sha=reconstruction.new_base_artifact_sha256
  if (new_base_sha!=hashlib.sha256(new_base).hexdigest()
      or old_base_sha!=hashlib.sha256(old_base).hexdigest()):
   raise CoreRuntimeError("source overlay base digest changed during preparation")
  self_manifest_sha=hashlib.sha256(_canonical_json(old_manifest)).hexdigest()
  next_manifest_sha=hashlib.sha256(_canonical_json(new_manifest)).hexdigest()
  prepared_primary_values={key:primary_values[key] for key in (
   "primary_record_sha256","soul_sha256","soul_signature","owner_prefix_sha256",
   "owner_prefix_length","owner_separator_hex","managed_block_sha256","prior_backup_sha256")}
  prepared_values={"purpose":"helper-only","cohort_transaction_id":cohort_id,
   "home_role":"jarvis-primary-home",
   "old_source_generation":old_core,"new_source_generation":old_core,
   "old_adapter_generation":old_adapter,"new_adapter_generation":new_adapter,
   "old_source_recipe_sha256":old_recipe,"new_source_recipe_sha256":new_recipe,
   "old_artifact_sha256":old_artifact,"new_artifact_sha256":new_artifact,
   "old_manifest_sha256":self_manifest_sha,"new_manifest_sha256":next_manifest_sha,
   "shared_manifest_sha256":shared_manifest,"shared_materialization_sha256":shared_tree,
   "shared_member_count":shared_count,"old_base_artifact_sha256":old_base_sha,
   "new_base_artifact_sha256":new_base_sha,
   "old_composed_artifact_sha256":old_artifact,"new_composed_artifact_sha256":new_artifact,
   "overlay_journal_sha256":reconstruction.overlay_journal_sha256,
   "overlay_contents":tuple(reconstruction.overlay_contents),
   "base_non_installer_manifest_sha256":reconstruction.base_non_installer_manifest_sha256,
   "composed_non_installer_manifest_sha256":reconstruction.composed_non_installer_manifest_sha256,
   "materialized_tree_sha256":reconstruction.materialized_tree_sha256,
   "installed_generation_journal_sha256":hashlib.sha256(old_installed_journal).hexdigest(),
   "installed_generation_custody_sha256":old_custody,
   "old_installed_journal_sha256":hashlib.sha256(old_installed_journal).hexdigest(),
   "resources_record_sha256":hashlib.sha256(resources_raw).hexdigest(),
   "discovery_record_sha256":hashlib.sha256(resources_raw).hexdigest(),
   "old_discovery_sha256":hashlib.sha256(resources_raw).hexdigest(),
   "overlay_record_sha256":hashlib.sha256(overlay_raw).hexdigest() if overlay_raw else _ABSENT_DIGEST,
   "obsidian_registration_state":obsidian_state,"obsidian_registration_sha256":obsidian_sha,
   **prepared_primary_values}
  prepared=_seal_prepared_same_materialization_transition(current_check=current_check,**prepared_values)
  state["prepared"]=prepared
  old_proof=_current_resources_overlay_artifact(old_base,
   overlay_record or {"schema":1,"base_artifact_sha256":old_base_sha,"skills":{}},
   overlay_contents,overlay_raw)
  if old_proof!=(old_archive,old_artifact):
   raise CoreRuntimeError("current owner overlay does not reproduce its exact installed A0")
  _write_resources_cas_artifact(new_base,new_base_sha)
  import_result=_run_same_materialization_import(prepared,new_archive,old_archive,
   cohort["owner_generation_backup_name"])
  installed_path=HERMES_HOME/"skills"/native._GENERATION
  new_installed_journal=_projection_file(installed_path/native._OWNER_FILE,owner=1000,
   group=1000,mode=0o600,maximum=2*1024*1024)
  _hash_generation_tree(HERMES_HOME,new_manifest,new_generation_files,new_artifact)
  if import_result.get("artifact_sha256")!=new_artifact:
   raise CoreRuntimeError("native helper-only importer returned a different generation")
  with _guarded_old_read_scope(old_read,purpose="resources-readback"):
   verified_archive,rpre_record=_adapter_update_current_resource_payload(
    overlay_snapshot=(overlay_record,overlay_contents,overlay_raw),reconstruction=reconstruction)
  _write_resources_cas_artifact(verified_archive,rpre_record["artifact_sha256"])
  rpre_raw=(json.dumps(rpre_record,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
  cohort["phase"]="resources-rebound"
  cohort["pre_switch_resources_record_sha256"]=hashlib.sha256(rpre_raw).hexdigest()
  recon=_adapter_update_reconstruction_row(reconstruction,cohort_id=cohort_id,
   phase="resources-rebound",old_core=old_core,new_core=old_core,
   old_recipe=old_recipe,new_recipe=new_recipe,
   old_marker=hashlib.sha256(old_installed_journal).hexdigest(),
   new_marker=hashlib.sha256(new_installed_journal).hexdigest(),
   old_discovery=hashlib.sha256(resources_raw).hexdigest(),
   new_discovery=hashlib.sha256(rpre_raw).hexdigest())
  cohort["reconstruction"]=recon
  cohort["reconstruction_sha256"]=hashlib.sha256(_canonical_json(recon)).hexdigest()
  cohort_raw=_write_adapter_update_cohort(cohort,expected_raw=cohort_raw)
  _atomic_replace(RESOURCES_RECORD,rpre_raw,0o600,ROOT_UID,ROOT_UID)
  if _projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
      mode=0o600,maximum=16*1024)!=rpre_raw:
   raise CoreRuntimeError("rebound Resources receipt did not persist exactly")
  state.update({"phase":"resources-rebound","cohort":cohort,"cohort_raw":cohort_raw,
   "resources_raw":rpre_raw})
  native_plugin_state["cohort_raw"]=cohort_raw
  old_read=_issue_guarded_old_read(cohort=cohort,cohort_raw=cohort_raw,record=record,
   journal_raw=raw_journal,old_unit=old_unit,old_launcher=old_launcher,pidfd=old_pidfd,
   pid=old_pid,process_identity_sha256=old_process_sha,purpose="primary-rebase-readback")
  state["old_read"]=old_read
  if primary_values["primary_record_sha256"]!=_ABSENT_DIGEST:
   from .primary_prompt_manager import rebase_identical_primary_binding
   with _guarded_old_read_scope(old_read,purpose="primary-rebase-readback"):
    rebase_identical_primary_binding(prepared)
   state["primary_raw"]=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
    group=ROOT_UID,mode=0o600,maximum=64*1024)
  with _guarded_old_read_scope(old_read,purpose="resources-readback"):
   if read_current_resources_discovery(core_source_generation=old_core).get("resources_state")!="discovered":
    raise CoreRuntimeError("rebound A1 discovery/current installed tree did not verify")
  from .remote import obsidian_owner_lifecycle as obsidian
  if (snapshots["obsidian_registration_state"]=="registered"
      and (obsidian.read_registration()[2]!=snapshots["obsidian_registration_sha256"]
       or _obsidian_vault_tree_sha256(obsidian.OWNER_DATA_ROOT/"obsidian-vault")
          !=snapshots["obsidian_vault_tree_sha256"])):
   raise CoreRuntimeError("Obsidian owner registration or vault changed during source preparation")
  if not verify_prepared_same_materialization_transition(prepared):
   raise CoreRuntimeError("prepared source/binding tuple changed before service stop")
  # No source or launcher byte is switched until all old-native and binding
  # readbacks above are complete and the captured old PIDFD is still held.
  _stop_captured_adapter_process(old_pidfd,old_pid,old_source,old_adapter,old_core,old_process_sha)
  if (_run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active"
      or _run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip() not in {"","0"}):
   raise CoreRuntimeError("old Core service returned during its guarded stop")
  if plugin_transition is not None:
   _run_native_plugin_transition("install")
  staged_digest=verify_staged_native_resources_plugin(deadline=time.monotonic()+35.0)
  if not re.fullmatch(r"[0-9a-f]{64}",str(staged_digest or "")):
   raise CoreRuntimeError("new native plugin staged pair did not verify after the guarded swap")
  _atomic_replace(UNIT,new_unit,0o644,ROOT_UID,ROOT_UID)
  _atomic_replace(LAUNCHER,new_launcher,0o755,ROOT_UID,ROOT_UID)
  _run(["systemctl","daemon-reload"])
  if (_projection_file(UNIT,owner=ROOT_UID,group=ROOT_UID,mode=0o644,maximum=256*1024)!=new_unit
      or _projection_file(LAUNCHER,owner=ROOT_UID,group=ROOT_UID,mode=0o755,maximum=256*1024)!=new_launcher
      or not _owned_unit_loaded()):
   raise CoreRuntimeError("new source guarded unit/launcher readback differs")
  starting={key:value for key,value in record.items() if not key.startswith("adapter_update_")}
  starting.update({"adapter_source":str(ADAPTER_SOURCE),"adapter_generation":new_adapter,
   "core_source_generation":old_core,"unit_sha256":new_unit_sha,"launcher_sha256":new_launcher_sha,
   "adapter_update_state":"starting","adapter_update_backup":backup_reference,
   "adapter_update_previous_source":str(old_source),"adapter_update_target_source":str(ADAPTER_SOURCE),
   "adapter_update_target_generation":new_adapter,"adapter_update_staged_plugin_sha256":staged_digest,
   "adapter_update_cohort_transaction_id":cohort_id})
  starting_raw=(json.dumps(starting,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
  starting_record=_bind_resources_record_to_starting_journal(rpre_record,starting_raw)
  starting_resources_raw=(json.dumps(starting_record,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
  cohort["phase"]="source-starting"
  cohort["starting_journal_sha256"]=hashlib.sha256(starting_raw).hexdigest()
  cohort["starting_resources_record_sha256"]=hashlib.sha256(starting_resources_raw).hexdigest()
  recon=_adapter_update_reconstruction_row(reconstruction,cohort_id=cohort_id,
   phase="source-starting",old_core=old_core,new_core=old_core,
   old_recipe=old_recipe,new_recipe=new_recipe,
   old_marker=hashlib.sha256(old_installed_journal).hexdigest(),
   new_marker=hashlib.sha256(new_installed_journal).hexdigest(),
   old_discovery=hashlib.sha256(resources_raw).hexdigest(),
   new_discovery=hashlib.sha256(starting_resources_raw).hexdigest())
  cohort["reconstruction"]=recon; cohort["reconstruction_sha256"]=hashlib.sha256(_canonical_json(recon)).hexdigest()
  cohort_raw=_write_adapter_update_cohort(cohort,expected_raw=cohort_raw)
  _atomic_replace(RESOURCES_RECORD,starting_resources_raw,0o600,ROOT_UID,ROOT_UID)
  _atomic_replace(JOURNAL,starting_raw,0o600,ROOT_UID,ROOT_UID)
  if (_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
       mode=0o600,maximum=16*1024)!=starting_resources_raw
      or _projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,
       mode=0o600,maximum=64*1024)!=starting_raw):
   raise CoreRuntimeError("starting source/Resources tuple did not persist exactly")
  state.update({"phase":"source-starting","cohort":cohort,"cohort_raw":cohort_raw,
   "journal_raw":starting_raw,"resources_raw":starting_resources_raw})
  _run(["systemctl","start",SERVICE]); _wait_for_listener()
  new_pidfd,new_pid,new_evidence,new_process_sha=_capture_adapter_service_process(
   ADAPTER_SOURCE,new_adapter,old_core)
  new_read=_issue_guarded_new_read(cohort=cohort,cohort_raw=cohort_raw,record=starting,
   journal_raw=starting_raw,resources_raw=starting_resources_raw,unit=new_unit,
   launcher=new_launcher,pidfd=new_pidfd,pid=new_pid,
   process_identity_sha256=new_process_sha,purpose="resources-readback")
  state["new_read"]=new_read
  with _guarded_new_read_scope(new_read,purpose="resources-readback"):
   if read_current_resources_discovery(core_source_generation=old_core).get("resources_state")!="discovered":
    raise CoreRuntimeError("new-source current Resources A1 readback failed")
   actual_archive,actual_resources=_verified_resources_payload()
  if (actual_archive!=new_archive or actual_resources.get("artifact_sha256")!=new_artifact
      or actual_resources.get("loaded_skill_inventory_sha256")!=starting_record.get("loaded_skill_inventory_sha256")
      or actual_resources.get("active_primary_prompt_sha256")!=starting_record.get("active_primary_prompt_sha256")):
   raise CoreRuntimeError("new Core startup Resources readback differs from its starting receipt")
  if initial_primary_transition is not None:
   from . import primary_prompt_manager as primary
   from .registry.primary_prompt import append_managed_block,render_managed_block
   prior_soul,prior_signature=primary._read_soul(sys.modules[__name__])
   source_prompt=new_generation_files.get("registry/profiles/hermes/SOUL.md")
   if not isinstance(source_prompt,bytes):
    raise CoreRuntimeError("initial-primary source prompt is unavailable")
   managed_block=render_managed_block(source_prompt)
   desired_soul,separator=append_managed_block(prior_soul,managed_block)
   if (hashlib.sha256(prior_soul).hexdigest()!=initial_primary_transition["prior_soul_sha256"]
       or tuple(prior_signature)!=tuple(initial_primary_transition["prior_soul_signature"])
       or hashlib.sha256(source_prompt).hexdigest()!=initial_primary_transition["source_prompt_sha256"]
       or hashlib.sha256(managed_block).hexdigest()!=initial_primary_transition["managed_block_sha256"]
       or hashlib.sha256(desired_soul).hexdigest()!=initial_primary_transition["desired_soul_sha256"]
       or separator.hex()!=initial_primary_transition["owner_separator_hex"]):
    raise CoreRuntimeError("initial-primary inputs differ from the exact prepared owner snapshot")
   current_cohort,current_cohort_raw=_read_adapter_update_cohort()
   current_journal=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
   current_resources=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
   current_cohort,current_cohort_raw=_arm_initial_primary_adoption(
    new_read=new_read,cohort=current_cohort,cohort_raw=current_cohort_raw)
   initial_custody=_issue_initial_primary_adoption_custody(
    cohort=current_cohort,cohort_raw=current_cohort_raw,journal_raw=current_journal,
    resources_raw=current_resources,unit=new_unit,launcher=new_launcher,pidfd=new_pidfd,
    pid=new_pid,process_identity_sha256=new_process_sha,prior_soul=prior_soul,
    prior_signature=prior_signature,source_prompt=source_prompt,managed_block=managed_block,
    desired_soul=desired_soul,owner_separator=separator)
   state["initial_primary_custody"]=initial_custody
   primary.adopt_primary_prompt_for_starting_cohort(initial_custody)
   current_cohort,current_cohort_raw=_read_adapter_update_cohort()
   initial_row=_initial_primary_transition_row(current_cohort)
   if initial_row.get("state")!="adopted":
    raise CoreRuntimeError("initial primary manager did not complete the sealed adoption")
   cohort,cohort_raw=current_cohort,current_cohort_raw
   primary_raw,primary_record,active_soul,active_signature=_initial_primary_record_and_soul()
   if (primary_record is None or primary_record.get("state")!="adopted"
       or hashlib.sha256(active_soul).hexdigest()!=initial_row["desired_soul_sha256"]
       or hashlib.sha256(primary_raw).hexdigest()!=initial_row["adopted_record_sha256"]
       or hashlib.sha256(active_soul).hexdigest()!=primary_record.get("result_soul_sha256")):
    raise CoreRuntimeError("initial primary adoption readback differs from its cohort row")
   primary_values={"primary_record_sha256":hashlib.sha256(primary_raw).hexdigest(),
    "soul_sha256":hashlib.sha256(active_soul).hexdigest(),
    "soul_signature":tuple(active_signature),
    "owner_prefix_sha256":primary_record.get("owner_prefix_sha256"),
    "owner_prefix_length":primary_record.get("owner_prefix_length"),
    "owner_separator_hex":primary_record.get("owner_separator_hex"),
    "managed_block_sha256":primary_record.get("managed_block_sha256"),
    "prior_backup_sha256":primary_record.get("owner_backup_name"),
    "native_effective_prompt_sha256":primary_record.get("native_effective_prompt_sha256")}
   if not re.fullmatch(r"[0-9a-f]{64}",str(primary_values["native_effective_prompt_sha256"] or "")):
    raise CoreRuntimeError("adopted primary manager did not bind the native loaded identity")
   state["primary_raw"]=primary_raw
   state["soul_sha256"]=primary_values["soul_sha256"]
   state["soul_signature"]=primary_values["soul_signature"]
   # The manager advances the cohort and Resources receipt after initial
   # adoption. Reissue custody for that exact current tuple before asking the
   # normal journal reader to validate the starting recipe.
   current_cohort,current_cohort_raw=_read_adapter_update_cohort()
   starting_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,
    mode=0o600,maximum=64*1024)
   starting_resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
    mode=0o600,maximum=16*1024)
   starting_record=json.loads(starting_raw)
   new_read=_issue_guarded_new_read(cohort=current_cohort,cohort_raw=current_cohort_raw,
    record=starting_record,journal_raw=starting_raw,resources_raw=starting_resources_raw,
    unit=new_unit,launcher=new_launcher,pidfd=new_pidfd,pid=new_pid,
    process_identity_sha256=new_process_sha,purpose="resources-readback")
   state["new_read"]=new_read
   with _guarded_new_read_scope(new_read,purpose="resources-readback"):
    starting=_journal()
    starting_raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,
     mode=0o600,maximum=64*1024)
    starting_resources_raw=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
     mode=0o600,maximum=16*1024)
    if (hashlib.sha256(starting_raw).hexdigest()!=new_read.starting_journal_sha256
        or hashlib.sha256(starting_resources_raw).hexdigest()!=new_read.starting_resources_record_sha256
        or not _validate_guarded_new_read(new_read)):
     raise CoreRuntimeError("initial adopted starting tuple changed during guarded journal read")
    state["resources_raw"]=starting_resources_raw
    if read_current_resources_discovery(core_source_generation=old_core).get("resources_state")!="discovered":
     raise CoreRuntimeError("initial adopted A1 Resources discovery did not verify")
    actual_archive,actual_resources=_verified_resources_payload()
   if (actual_archive!=new_archive
       or actual_resources.get("active_primary_prompt_sha256")!=primary_values["soul_sha256"]):
    raise CoreRuntimeError("initial adopted primary differs from current native Resources readback")
  startup_context={"cohort":cohort,"cohort_raw":cohort_raw,"record":starting,
   "journal_raw":starting_raw,"resources_raw":starting_resources_raw,"unit":new_unit,
   "launcher":new_launcher,"pidfd":new_pidfd,"pid":new_pid,"identity":new_process_sha,
   "new_read":new_read,
   "evidence":new_evidence,"adapter":new_adapter,"core":old_core,"artifact":new_artifact,
   "primary":state["primary_raw"],"primary_source":primary_values["soul_sha256"],
   "soul":primary_values.get("native_effective_prompt_sha256",primary_values["soul_sha256"]),
   "resources":actual_resources,"obsidian_state":obsidian_state,"obsidian_sha":obsidian_sha,
   "obsidian_vault":snapshots["obsidian_vault_tree_sha256"]}
  startup_token=_ADAPTER_STARTUP_COHORT_CONTEXT.set(startup_context)
  try: _prove_new_cohort_startup_chat()
  finally: _ADAPTER_STARTUP_COHORT_CONTEXT.reset(startup_token)
  if (not _validate_guarded_new_read(new_read)
      or _adapter_process_identity(ADAPTER_SOURCE,new_adapter,old_core,new_pid)[1]!=new_process_sha):
   raise CoreRuntimeError("new Core startup proof lost its held source/process tuple")
  with _guarded_new_read_scope(new_read,purpose="resources-readback"):
   fresh_archive,fresh_resources=_verified_resources_payload()
   if (fresh_archive!=new_archive
       or any(fresh_resources.get(key)!=actual_resources.get(key)
              for key in set(actual_resources)-{"observed_at_utc"})):
    raise CoreRuntimeError("new Core Resources bindings changed during lifecycle proof")
  current_selection=verify_native_resources_plugin_selection()
  from . import primary_prompt_manager as primary
  if primary_values["primary_record_sha256"]!=_ABSENT_DIGEST:
   current_soul,current_signature=primary._read_soul(sys.modules[__name__])
   current_primary=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
    group=ROOT_UID,mode=0o600,maximum=64*1024)
   if (hashlib.sha256(current_soul).hexdigest()!=primary_values["soul_sha256"]
       or tuple(current_signature)!=primary_values["soul_signature"]
       or hashlib.sha256(current_primary).hexdigest()!=hashlib.sha256(state["primary_raw"]).hexdigest()):
    raise CoreRuntimeError("adopted primary binding changed during new-source lifecycle proof")
  elif initial_primary_transition is not None:
   current_soul,current_signature=primary._read_soul(sys.modules[__name__])
   current_primary=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
    group=ROOT_UID,mode=0o600,maximum=64*1024)
   current_cohort,_current_cohort_raw=_read_adapter_update_cohort()
   initial_row=_initial_primary_transition_row(current_cohort)
   if (initial_row.get("state")!="adopted"
       or hashlib.sha256(current_soul).hexdigest()!=initial_row.get("desired_soul_sha256")
       or tuple(current_signature)!=primary_values["soul_signature"]
       or hashlib.sha256(current_primary).hexdigest()!=initial_row.get("adopted_record_sha256")):
    raise CoreRuntimeError("initial primary adoption changed during new-source lifecycle proof")
  else:
   try: primary_now=_projection_file(PRIMARY_PROMPT_JOURNAL,owner=ROOT_UID,
    group=ROOT_UID,mode=0o600,maximum=64*1024)
   except FileNotFoundError: primary_now=None
   if primary_now is not None:
    raise CoreRuntimeError("primary adoption appeared during an unadopted source cohort")
  _overlay_now,_overlay_contents_now,overlay_raw_now=_read_adapter_overlay_snapshot()
  if overlay_raw_now!=overlay_raw:
   raise CoreRuntimeError("owner Resources overlay changed during new-source lifecycle proof")
  from .remote import obsidian_owner_lifecycle as obsidian
  if (getattr(current_selection,"selection_sha256",None)!=selection_digest
      or _core_source_generation()!=old_core
      or _current_native_adapter_generation(deadline=time.monotonic()+35.0)!=new_adapter
      or (obsidian_state=="registered" and
          (obsidian.read_registration()[2]!=obsidian_sha
           or _obsidian_vault_tree_sha256(obsidian.OWNER_DATA_ROOT/"obsidian-vault")
              !=snapshots["obsidian_vault_tree_sha256"]))):
   raise CoreRuntimeError("source, selection or Obsidian custody changed during lifecycle proof")
  cohort["phase"]="bindings-verified"
  recon=dict(cohort["reconstruction"]); recon["phase"]="bindings-verified"
  cohort["reconstruction"]=recon; cohort["reconstruction_sha256"]=hashlib.sha256(_canonical_json(recon)).hexdigest()
  cohort_raw=_write_adapter_update_cohort(cohort,expected_raw=cohort_raw)
  final={key:value for key,value in starting.items()}
  final["adapter_update_state"]="active"
  final_raw=(json.dumps(final,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
  final_resources=_bind_resources_record_to_starting_journal(actual_resources,final_raw)
  final_resources_raw=(json.dumps(final_resources,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
  # Record both exact final bytes before replacing either file. The startup
  # gate still admits only J_s/R_s until C reaches committed.
  cohort["new_journal_sha256"]=hashlib.sha256(final_raw).hexdigest()
  cohort["new_resources_record_sha256"]=hashlib.sha256(final_resources_raw).hexdigest()
  recon=dict(cohort["reconstruction"])
  recon["new_discovery_sha256"]=cohort["new_resources_record_sha256"]
  cohort["reconstruction"]=recon
  cohort["reconstruction_sha256"]=hashlib.sha256(_canonical_json(recon)).hexdigest()
  cohort_raw=_write_adapter_update_cohort(cohort,expected_raw=cohort_raw)
  _atomic_replace(RESOURCES_RECORD,final_resources_raw,0o600,ROOT_UID,ROOT_UID)
  _atomic_replace(JOURNAL,final_raw,0o600,ROOT_UID,ROOT_UID)
  recon=dict(cohort["reconstruction"]); recon["phase"]="committed"
  recon["new_discovery_sha256"]=hashlib.sha256(final_resources_raw).hexdigest()
  cohort["reconstruction"]=recon; cohort["reconstruction_sha256"]=hashlib.sha256(_canonical_json(recon)).hexdigest()
  cohort["phase"]="committed"
  cohort_raw=_write_adapter_update_cohort(cohort,expected_raw=cohort_raw)
  final_record=_journal()
  if (final_record.get("adapter_source")!=str(ADAPTER_SOURCE)
      or final_record.get("adapter_generation")!=new_adapter
      or read_current_resources_discovery(core_source_generation=old_core).get("resources_state")!="discovered"):
   raise CoreRuntimeError("committed source/Resources/discovery cohort failed final readback")
  return "journal-owned Hermes core and preserved Resources bindings updated to the verified adapter generation"
 except Exception as exc:
  recovery_cohort=None
  if backup_reference is not None:
   try: recovery_cohort,_=_read_adapter_update_cohort(allow_absent=True)
   except Exception: recovery_cohort=None
  if (backup_reference is not None and type(recovery_cohort) is dict
      and recovery_cohort.get("cohort_transaction_id")==cohort_id):
   try:
    active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
    if active=="active" and not any(_owned_listener_pidfd(adapter_source=source)
      for source in (old_source,ADAPTER_SOURCE)):
     raise CoreRuntimeError("running Core process is outside both journaled source generations")
    _restore_adapter_update_backup(backup_reference,allowed_sources=(old_source,ADAPTER_SOURCE))
   except Exception:
    raise CoreRuntimeError("adapter cohort failed; exact protected recovery backup retained") from None
  if isinstance(exc,CoreRuntimeError): raise
  raise CoreRuntimeError("adapter cohort failed; prior source and binding recovery was attempted") from None
 finally:
  _ADAPTER_STARTUP_COHORT_CONTEXT.set(None)
  if new_pidfd is not None:
   _GUARDED_NEW_READ_ACTIVE.clear()
   os.close(new_pidfd)
  if prepared is not None:
   with _PREPARED_SAME_MATERIALIZATION_LOCK:
    _PREPARED_SAME_MATERIALIZATION.pop(id(prepared),None)
  _GUARDED_OLD_READ_ACTIVE.clear()
  os.close(old_pidfd)
  _NATIVE_PLUGIN_TRANSITION_STATE.reset(native_plugin_state_token)

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
 _recover_interrupted_adapter_update()
 launcher,unit=_launcher(),_unit(cohort_gate=False)
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
         "recover_owned_core_from_adapter_migration","refresh_resources_discovery",
         "rollback","status","update_owned_core_adapter"]
