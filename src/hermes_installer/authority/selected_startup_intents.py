"""Setup-side one-use startup intent custody for HI-T197.1."""
from __future__ import annotations
import fcntl, hashlib, json, os, re, secrets, stat, time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from .types import AuthorityDenied, canonical_bytes

_FIELDS = frozenset({"schema","purpose","intent_handle","nonce_sha256","activation_id",
 "daemon_unit_id","daemon_invocation_id","setup_session_id","setup_actor_witness_sha256",
 "bootstrap_transaction_handle","committed_transaction_id","generation_id","service_generation_digest",
 "publication_receipt_handle","publication_sha256","remote_enrollment_id","remote_startup_row_sha256",
 "network_enrollment_id","network_row_sha256","role_recipe_records_sha256","principal_binding_sha256",
 "original_setup_deadline_monotonic","issued_monotonic","expires_monotonic"})
_RECORD = frozenset({"schema","intent_body","intent_sha256","state","accepted_monotonic",
 "outcome_handle","outcome_sha256"})
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DIR = os.O_RDONLY | getattr(os,"O_DIRECTORY",0) | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_CLOEXEC",0)
_SUBROOT = "selected-startup-intents"
_SEAL = object()

class SelectedStartupIntentUnavailable(AuthorityDenied):
    def __init__(self, message: str): super().__init__("selected.startup.intent", message)

def _sha(value: Mapping[str,Any]) -> str: return hashlib.sha256(canonical_bytes(dict(value))).hexdigest()
def _pairs(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError("duplicate JSON field")
        out[k]=v
    return out

@dataclass(frozen=True, slots=True, repr=False)
class RootSetupSelectedStartupIntent:
    intent_handle: str
    intent_sha256: str
    nonce: bytes = field(repr=False, compare=False)
    activation_id: str
    expires_monotonic: float
    body: Mapping[str,Any] = field(repr=False, compare=False)
    issuer: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)
    def __post_init__(self):
        if (self._seal is not _SEAL or type(self.body) is not MappingProxyType
            or not _HANDLE.fullmatch(self.intent_handle) or not _HEX64.fullmatch(self.intent_sha256)
            or type(self.nonce) is not bytes or len(self.nonce)!=32
            or not _HEX32.fullmatch(self.activation_id)):
            raise TypeError("startup intent is issued by a live setup owner")
    def __repr__(self): return "RootSetupSelectedStartupIntent(<protected>)"

@dataclass(frozen=True, slots=True, repr=False)
class RootAcceptedSelectedStartupIntent:
    intent_handle: str
    intent_sha256: str
    body: Mapping[str,Any] = field(repr=False, compare=False)
    accepted_monotonic: float
    activation_id: str
    _journal: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)
    def __post_init__(self):
        if (self._seal is not _SEAL or type(self._journal) is not RootSetupSelectedStartupIntentJournal
            or type(self.body) is not MappingProxyType or not _HANDLE.fullmatch(self.intent_handle)
            or not _HEX64.fullmatch(self.intent_sha256)):
            raise TypeError("accepted intent is issued by its protected journal")
    def __repr__(self): return "RootAcceptedSelectedStartupIntent(<protected>)"

class RootSetupSelectedStartupIntentJournal:
    """Root-owned 0700 ledger with no-follow, inode-checked 0600 records."""
    def __init__(self, issuer, root_journal, *, create, receiver=None, active_receipt=None,
                 activation_id=None):
        from hermes_installer.protected_enrollment import RootJournalSelection
        from .listener_activation import RootAuthorityListenerActivationReceiver, RootActiveAuthorityListenerReceipt
        if ((issuer is not None and type(issuer) is not RootSetupSelectedStartupIntentIssuer)
            or (issuer is None and receiver is None)
            or type(root_journal) is not RootJournalSelection
            or root_journal.root_id!="installer-authority-journal-v1"
            or (receiver is None)!=(active_receipt is None)
            or (receiver is not None and type(receiver) is not RootAuthorityListenerActivationReceiver)
            or (active_receipt is not None and type(active_receipt) is not RootActiveAuthorityListenerReceipt)
            or os.geteuid()!=0):
            raise SelectedStartupIntentUnavailable("exact setup issuer, protected journal, and optional receiver are required")
        self.issuer,self.root_journal=issuer,root_journal
        self.receiver,self.active_receipt=receiver,active_receipt
        self.activation_id=None
        self._closed=False; self._root_fd=self._ledger_fd=-1
        try:
            self._root_fd=os.open(root_journal.path,_DIR)
            root=os.fstat(self._root_fd); named=root_journal.path.lstat()
            if (not stat.S_ISDIR(root.st_mode) or (root.st_dev,root.st_ino)!=(root_journal.device,root_journal.inode)
                or (named.st_dev,named.st_ino)!=(root.st_dev,root.st_ino)
                or root.st_uid!=0 or root.st_gid!=0 or stat.S_IMODE(root.st_mode)!=0o700):
                raise ValueError()
            if create:
                try:
                    os.mkdir(_SUBROOT,0o700,dir_fd=self._root_fd)
                    os.chown(_SUBROOT,0,0,dir_fd=self._root_fd,follow_symlinks=False)
                    os.chmod(_SUBROOT,0o700,dir_fd=self._root_fd,follow_symlinks=False)
                    os.fsync(self._root_fd)
                except FileExistsError: pass
            self._ledger_fd=os.open(_SUBROOT,_DIR,dir_fd=self._root_fd)
            ledger=os.fstat(self._ledger_fd)
            if not stat.S_ISDIR(ledger.st_mode) or ledger.st_uid!=0 or ledger.st_gid!=0 or stat.S_IMODE(ledger.st_mode)!=0o700: raise ValueError()
            self._root_identity=(root.st_dev,root.st_ino); self._ledger_identity=(ledger.st_dev,ledger.st_ino)
        except Exception:
            self.close()
            raise SelectedStartupIntentUnavailable("protected startup intent ledger is unavailable") from None
        self.activation_id = issuer.activation_id if issuer is not None else activation_id
        if not _HEX32.fullmatch(self.activation_id or ""):
            self.close()
            raise SelectedStartupIntentUnavailable("startup journal activation ID is unavailable")
        if receiver is not None:
            try:
                current = receiver.current_active_receipt()
                if (current is not active_receipt or current.activation_id != self.activation_id
                        or receiver.activation_id != self.activation_id):
                    raise ValueError("receiver activation changed")
            except Exception:
                self.close()
                raise SelectedStartupIntentUnavailable(
                    "daemon startup journal does not match the current adopted receiver") from None
        if issuer is not None:
            if issuer.journal not in (None, self):
                self.close()
                raise SelectedStartupIntentUnavailable("setup issuer already owns another startup journal")
            issuer.journal = self
            issuer.session_store.attach_selected_startup_intent_journal(self)
    @classmethod
    def from_current_root_setup(cls, issuer, root_journal): return cls(issuer,root_journal,create=True)
    @classmethod
    def from_adopted_daemon(cls, root_journal, activation_id, receiver, active_receipt):
        return cls(None,root_journal,create=False,receiver=receiver,
                   active_receipt=active_receipt,activation_id=activation_id)
    def _verify_dirs(self):
        if self._closed: raise SelectedStartupIntentUnavailable("startup ledger is closed")
        root=os.fstat(self._root_fd); ledger=os.fstat(self._ledger_fd)
        rn=self.root_journal.path.lstat(); ln=os.stat(_SUBROOT,dir_fd=self._root_fd,follow_symlinks=False)
        if ((root.st_dev,root.st_ino)!=self._root_identity or (rn.st_dev,rn.st_ino)!=self._root_identity
            or root.st_uid!=0 or root.st_gid!=0 or stat.S_IMODE(root.st_mode)!=0o700
            or (ledger.st_dev,ledger.st_ino)!=self._ledger_identity or (ln.st_dev,ln.st_ino)!=self._ledger_identity
            or ledger.st_uid!=0 or ledger.st_gid!=0 or stat.S_IMODE(ledger.st_mode)!=0o700):
            raise SelectedStartupIntentUnavailable("startup ledger directory custody changed")
    def _lock(self):
        self._verify_dirs()
        fd=os.open(".ledger.lock",os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),0o600,dir_fd=self._ledger_fd)
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o600:
            os.close(fd); raise SelectedStartupIntentUnavailable("startup ledger lock is unprotected")
        fcntl.flock(fd,fcntl.LOCK_EX); self._verify_dirs(); return fd
    def _read(self,handle):
        self._verify_dirs()
        if not isinstance(handle,str) or not _HANDLE.fullmatch(handle): raise SelectedStartupIntentUnavailable("startup handle is malformed")
        fd=os.open(handle+".json",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=self._ledger_fd)
        try:
            st=os.fstat(fd)
            named=os.stat(handle+".json",dir_fd=self._ledger_fd,follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>262144: raise ValueError()
            if (named.st_dev,named.st_ino)!=(st.st_dev,st.st_ino) or not stat.S_ISREG(named.st_mode): raise ValueError()
            raw=b""
            while len(raw)<=262144:
                b=os.read(fd,min(8192,262145-len(raw)))
                if not b: break
                raw+=b
            value=json.loads(raw.decode("utf-8"),object_pairs_hook=_pairs); body=value.get("intent_body")
            if (len(raw)!=st.st_size or set(value)!=_RECORD or type(value["schema"]) is not int or value["schema"]!=1
                or not isinstance(body,dict) or set(body)!=_FIELDS or type(body["schema"]) is not int or body["schema"]!=1 or body["purpose"]!="root-selected-startup-intent-v1"
                or body["activation_id"]!=self.activation_id or body["intent_handle"]!=handle
                or value["intent_sha256"]!=_sha(body) or value["state"] not in {"created","accepted","consumed","completed","cancelled"}
                or type(body["issued_monotonic"]) not in (int,float) or type(body["expires_monotonic"]) not in (int,float)
                or type(body["original_setup_deadline_monotonic"]) not in (int,float)
                or not body["issued_monotonic"]<body["expires_monotonic"]<=body["original_setup_deadline_monotonic"]
                or body["expires_monotonic"]-body["issued_monotonic"]>30.0
                or not _HEX64.fullmatch(body["nonce_sha256"])):
                raise ValueError()
            if value["state"]=="completed":
                if not _HANDLE.fullmatch(value["outcome_handle"] or "") or not _HEX64.fullmatch(value["outcome_sha256"] or ""): raise ValueError()
            elif value["outcome_handle"] is not None or value["outcome_sha256"] is not None: raise ValueError()
            named_after=os.stat(handle+".json",dir_fd=self._ledger_fd,follow_symlinks=False)
            if (named_after.st_dev,named_after.st_ino)!=(st.st_dev,st.st_ino): raise ValueError()
            return value,(st.st_dev,st.st_ino)
        except Exception: raise SelectedStartupIntentUnavailable("startup record failed closed validation") from None
        finally: os.close(fd)
    def _write(self,handle,value,old):
        name=".tmp."+secrets.token_hex(16); raw=canonical_bytes(dict(value))
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),0o600,dir_fd=self._ledger_fd)
        try:
            os.fchown(fd,0,0); os.fchmod(fd,0o600); view=memoryview(raw)
            while view:
                n=os.write(fd,view)
                if n<=0: raise OSError("short record write")
                view=view[n:]
            os.fsync(fd)
        finally: os.close(fd)
        try:
            filename=handle+".json"
            if old is None:
                try: os.stat(filename,dir_fd=self._ledger_fd,follow_symlinks=False)
                except FileNotFoundError: pass
                else: raise SelectedStartupIntentUnavailable("startup handle already exists")
            elif self._read(handle)[1]!=old: raise SelectedStartupIntentUnavailable("startup record changed during CAS")
            os.replace(name,filename,src_dir_fd=self._ledger_fd,dst_dir_fd=self._ledger_fd); os.fsync(self._ledger_fd)
        finally:
            try: os.unlink(name,dir_fd=self._ledger_fd)
            except OSError: pass
    def issue(self,body,nonce):
        if (self.issuer is None or not isinstance(body,Mapping) or set(body)!=_FIELDS
            or type(body.get("schema")) is not int or body["schema"]!=1
            or body["purpose"]!="root-selected-startup-intent-v1" or body["activation_id"]!=self.activation_id
            or type(nonce)is not bytes or len(nonce)!=32 or body["nonce_sha256"]!=hashlib.sha256(nonce).hexdigest()):
            raise SelectedStartupIntentUnavailable("intent body differs from closed v197 schema")
        self.issuer._authorize_intent_issue(body,nonce)
        lock=self._lock()
        try: self._write(body["intent_handle"],{"schema":1,"intent_body":dict(body),"intent_sha256":_sha(body),
             "state":"created","accepted_monotonic":None,"outcome_handle":None,"outcome_sha256":None},None)
        finally: fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
    def accept(self,handle,digest,nonce,receiver,receipt):
        if receiver is not self.receiver or receipt is not self.active_receipt or not _HEX64.fullmatch(digest) or not _HEX64.fullmatch(nonce):
            raise SelectedStartupIntentUnavailable("request belongs to another receiver")
        obs=receiver.observe_active_current(receipt); adopted=receiver._read_current_adopted_record()
        receiver._verify_setup_peer(adopted); lock=self._lock()
        try:
            row,identity=self._read(handle); body=row["intent_body"]; now=time.monotonic()
            if (row["state"]!="created" or row["intent_sha256"]!=digest
                or body["nonce_sha256"]!=hashlib.sha256(bytes.fromhex(nonce)).hexdigest()
                or body["activation_id"]!=obs.activation_id or body["daemon_unit_id"]!=obs.daemon_unit_id
                or body["daemon_invocation_id"]!=obs.daemon_invocation_id
                or body["publication_receipt_handle"]!=obs.publication_receipt_handle
                or body["publication_sha256"]!=obs.publication_sha256
                or body["service_generation_digest"]!=obs.service_generation_digest
                or body["setup_session_id"]!=adopted["setup_session_id"]
                or body["setup_actor_witness_sha256"]!=adopted["setup_actor_binding_sha256"]
                or now<body["issued_monotonic"] or now>=body["expires_monotonic"]
                or now>=body["original_setup_deadline_monotonic"]):
                raise SelectedStartupIntentUnavailable("intent source, peer, deadline, or nonce is stale")
            row["state"]="accepted"; row["accepted_monotonic"]=now; self._write(handle,row,identity)
            return self._accepted(row)
        finally: fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
    def _accepted(self,row):
        b=dict(row["intent_body"])
        return RootAcceptedSelectedStartupIntent(b["intent_handle"],row["intent_sha256"],MappingProxyType(b),
            row["accepted_monotonic"],self.activation_id,self,_SEAL)
    def resolve_current_accepted_intent_for_handle(self,handle,receiver,receipt):
        if receiver is not self.receiver or receipt is not self.active_receipt: raise SelectedStartupIntentUnavailable("foreign receiver")
        obs=receiver.observe_active_current(receipt); adopted=receiver._read_current_adopted_record(); receiver._verify_setup_peer(adopted)
        row,_=self._read(handle); b=row["intent_body"]
        if (row["state"] not in {"accepted","consumed"} or b["activation_id"]!=obs.activation_id
            or b["daemon_unit_id"]!=obs.daemon_unit_id or b["daemon_invocation_id"]!=obs.daemon_invocation_id
            or b["publication_sha256"]!=obs.publication_sha256 or b["service_generation_digest"]!=obs.service_generation_digest
            or b["setup_session_id"]!=adopted["setup_session_id"]):
            raise SelectedStartupIntentUnavailable("accepted intent is no longer current")
        return self._accepted(row)
    def mark_consumed(self,accepted):
        if type(accepted)is not RootAcceptedSelectedStartupIntent or accepted._journal is not self: raise SelectedStartupIntentUnavailable("foreign accepted intent")
        self.resolve_current_accepted_intent_for_handle(accepted.intent_handle,self.receiver,self.active_receipt)
        lock=self._lock()
        try:
            row,identity=self._read(accepted.intent_handle)
            if row["state"]!="accepted" or row["intent_sha256"]!=accepted.intent_sha256: raise SelectedStartupIntentUnavailable("startup intent replay")
            row["state"]="consumed"; self._write(accepted.intent_handle,row,identity)
        finally: fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
        return self.resolve_current_accepted_intent_for_handle(accepted.intent_handle,self.receiver,self.active_receipt)
    def commit_completed_outcome(self,accepted,outcome):
        # Runtime owner supplies only a concrete issuer-owned outcome, never an ACK.
        from .selected_startup_authority import RootSelectedStartupTerminalOutcome
        if type(accepted)is not RootAcceptedSelectedStartupIntent or accepted._journal is not self or type(outcome)is not RootSelectedStartupTerminalOutcome:
            raise SelectedStartupIntentUnavailable("completion requires the daemon's typed actual process outcome")
        self.resolve_current_accepted_intent_for_handle(accepted.intent_handle,self.receiver,self.active_receipt)
        body=outcome.public_projection()
        if body.get("intent_handle")!=accepted.intent_handle or body.get("intent_sha256")!=accepted.intent_sha256 or body.get("activation_id")!=self.activation_id:
            raise SelectedStartupIntentUnavailable("terminal outcome does not join the accepted intent")
        outcome_handle=secrets.token_urlsafe(32); digest=_sha(body); lock=self._lock()
        try:
            row,identity=self._read(accepted.intent_handle)
            if row["state"]!="consumed": raise SelectedStartupIntentUnavailable("intent is not consumed")
            row["state"]="completed"; row["outcome_handle"]=outcome_handle; row["outcome_sha256"]=digest
            self._write(accepted.intent_handle,row,identity)
        finally: fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
        return outcome_handle,digest
    def resolve_current_completed_intent(self,handle,outcome_handle,digest):
        if self.receiver is None or self.active_receipt is None: raise SelectedStartupIntentUnavailable("daemon outcome resolution unavailable")
        if self.receiver is not None:
            self.receiver.observe_active_current(self.active_receipt)
        row,_=self._read(handle)
        if (row["state"]!="completed" or row["outcome_handle"]!=outcome_handle or row["outcome_sha256"]!=digest):
            raise SelectedStartupIntentUnavailable("outcome is not the current completed result")
        # The journal's schema intentionally stores only a reference. The
        # daemon's issuer-owned process/outcome registry must resolve the
        # concrete terminal and cleanup receipts from this exact pair.
        resolver = getattr(self.receiver, "resolve_selected_startup_outcome", None)
        if self.receiver is not None and callable(resolver):
            body = resolver(handle, outcome_handle, digest)
            if not isinstance(body, Mapping) or _sha(body) != digest:
                raise SelectedStartupIntentUnavailable("daemon outcome registry returned a stale result")
            self.receiver.observe_active_current(self.active_receipt)
            return MappingProxyType(dict(body))
        if self.receiver is None:
            # The setup process verifies the returned reference against the
            # original issuer's retained source owner when available.
            source_resolver = getattr(self.issuer, "resolve_current_startup_outcome", None)
            if callable(source_resolver):
                return MappingProxyType(dict(source_resolver(handle, outcome_handle, digest)))
        raise SelectedStartupIntentUnavailable("actual startup terminal/cleanup outcome resolver is unavailable")
    def cancel_for_setup_session(self,session_handle):
        from .bootstrap_enrollment import RootSetupSessionHandle
        if (self.issuer is None or type(session_handle)is not RootSetupSessionHandle
            or not secrets.compare_digest(session_handle._instance_seal,self.issuer.session_store._instance_seal)):
            raise SelectedStartupIntentUnavailable("foreign setup cancellation handle")
        lock=self._lock()
        try:
            for name in os.listdir(self._ledger_fd):
                if not name.endswith(".json") or not _HANDLE.fullmatch(name[:-5]): continue
                h=name[:-5]; row,identity=self._read(h)
                if row["intent_body"]["setup_session_id"]==session_handle.session_id and row["state"] not in {"completed","cancelled"}:
                    row["state"]="cancelled"; self._write(h,row,identity)
        finally: fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
    def cancel_for_activation(self):
        lock=self._lock()
        try:
            for name in os.listdir(self._ledger_fd):
                if not name.endswith(".json") or not _HANDLE.fullmatch(name[:-5]): continue
                handle=name[:-5]; row,identity=self._read(handle)
                if row["intent_body"].get("activation_id")==self.activation_id and row["state"] not in {"completed","cancelled"}:
                    row["state"]="cancelled"; self._write(handle,row,identity)
        finally: fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
    def close(self):
        if self._closed:return
        self._closed=True
        for fd in (self._ledger_fd,self._root_fd):
            if fd>=0:
                try:os.close(fd)
                except OSError:pass
        self._ledger_fd=self._root_fd=-1

class RootSetupSelectedStartupIntentIssuer:
    def __init__(self,binding,held_release,own_actor,activation_supervisor):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .listener_activation import RootAuthorityListenerActivationSupervisor
        from .bootstrap_enrollment import RootSetupSessionStore
        session=getattr(binding,"_session",None); store=getattr(getattr(session,"_factory",None),"session_store",None)
        if (type(binding)is not RootSelectedInstallationBinding or type(held_release)is not VerifiedInstallerReleaseReceipt
            or type(own_actor)is not RootActorObservation or type(activation_supervisor)is not RootAuthorityListenerActivationSupervisor
            or activation_supervisor.binding is not binding or activation_supervisor.held_release is not held_release
            or activation_supervisor.current_actor is not own_actor or not isinstance(store,RootSetupSessionStore)):
            raise SelectedStartupIntentUnavailable("exact live root setup and adopted supervisor are required")
        own_actor.verify_current(held_release); session._check_live()
        self.binding,self.held_release,self.own_actor=binding,held_release,own_actor
        self.supervisor,self.session_store,self.session=activation_supervisor,store,session
        receipts=[item for item in activation_supervisor._transactions.values()]
        if len(receipts)!=1:
            raise SelectedStartupIntentUnavailable("startup issuer requires one current adopted listener")
        activation_supervisor.verify_active_current(receipts[0])
        self.activation_id=receipts[0].activation_id; self.journal=None; self._issuer=object(); self._issued={}
        if activation_supervisor._selected_startup_intent_issuer not in (None,self):
            raise SelectedStartupIntentUnavailable("activation supervisor already has a startup intent issuer")
        activation_supervisor._selected_startup_intent_issuer=self
    @classmethod
    def from_current_root_setup(cls,binding,held_release,own_actor,activation_supervisor):
        return cls(binding,held_release,own_actor,activation_supervisor)
    def duplicate_setup_actor_pidfd(self,session):
        if session is not self.session: raise SelectedStartupIntentUnavailable("exact retained setup session required")
        try:
            live=self.session_store._live(session._handle); self.own_actor.verify_current(self.held_release)
            if live.record["root_actor_identity"]["pid"]!=self.own_actor.pid: raise ValueError()
            return os.dup(live.pidfd)
        except Exception: raise SelectedStartupIntentUnavailable("current setup PIDFD is unavailable") from None
    def issue_selected_startup_intent(self,session,remote_enrollment_id):
        if session is not self.session: raise SelectedStartupIntentUnavailable("exact retained setup session required")
        # No setup-side RootRuntimeBindings/source owner currently resolves remote,
        # network, process recipe, native principal and overlay proof. The ID alone
        # is deliberately insufficient to mint any delegated authority.
        raise SelectedStartupIntentUnavailable(
            "setup has no current typed remote/network/role/principal/patch source resolver; intent not minted")
    def _authorize_intent_issue(self,body,nonce):
        issued=self._issued.get(body.get("intent_handle"))
        if (issued is None or issued[0]!=dict(body) or not secrets.compare_digest(issued[1],nonce)
            or body.get("setup_session_id")!=self.session._handle.session_id):
            raise SelectedStartupIntentUnavailable("intent body was not retained by this current setup issuer")
        self.session._check_live(); self.held_release.verify_current(); self.own_actor.verify_current(self.held_release)
    def verify_current(self,intent):
        if type(intent)is not RootSetupSelectedStartupIntent or intent.issuer is not self or intent._seal is not _SEAL or intent.expires_monotonic<=time.monotonic():
            raise SelectedStartupIntentUnavailable("foreign or expired startup intent")
        self.session._check_live(); self.held_release.verify_current(); self.own_actor.verify_current(self.held_release)
