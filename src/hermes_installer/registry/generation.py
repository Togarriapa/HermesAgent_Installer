"""Journaled immutable generations using the installer's existing mutation lease."""
from __future__ import annotations
import hashlib, json, os, shutil, stat, tempfile
from pathlib import Path
from typing import Mapping
from hermes_installer.state import Journal, OwnedRoot

class GenerationError(RuntimeError):
    """Generation identity, ownership or integrity did not verify."""

class GenerationStore:
    def __init__(self, owned_root: OwnedRoot, journal: Journal, *, mutation_locked: bool):
        if not mutation_locked:
            raise RuntimeError("GenerationStore must be constructed inside the exclusive installer mutation lease")
        self.owned=owned_root; self.journal=journal
        root=owned_root.root
        marker=root/".hermes-installer-owned"
        if root.is_symlink() or not root.is_dir() or marker.is_symlink() or not marker.is_file():
            raise GenerationError("installer-owned root is not initialized")
        self.root=owned_root.path("generations")
        self.root.mkdir(mode=0o700,exist_ok=True)
        self._private_directory(self.root)

    @staticmethod
    def _validate_id(value:str)->str:
        if not value or len(value)>96 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in value):
            raise ValueError("invalid generation id")
        return value

    @staticmethod
    def _private_file(path:Path,*,allow_readonly:bool=False):
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
            raise GenerationError(f"generation file owner or permissions are invalid: {path.name}")
        mode=stat.S_IMODE(info.st_mode)
        if mode not in ({0o400,0o500,0o600} if allow_readonly else {0o600,0o500}):
            raise GenerationError(f"generation file mode is invalid: {path.name}")

    @staticmethod
    def _private_directory(path:Path):
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
            raise GenerationError(f"generation directory owner or permissions are invalid: {path.name}")

    @staticmethod
    def _fsync_dir(path:Path):
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
        try:os.fsync(fd)
        finally:os.close(fd)

    @staticmethod
    def _manifest_digest(manifest:dict)->str:
        payload=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()
        return hashlib.sha256(payload).hexdigest()

    def _operation(self,generation_id:str):
        return self.journal.operation("registry-generation:"+generation_id)

    def stage(self,generation_id:str,files:Mapping[str,bytes])->Path:
        generation_id=self._validate_id(generation_id)
        if not files:raise GenerationError("refusing an empty generation")
        target=self.root/generation_id
        if target.exists() or target.is_symlink():raise GenerationError("generation already exists; immutable generations are never replaced")
        stage=Path(tempfile.mkdtemp(prefix=".stage-",dir=self.root)); os.chmod(stage,0o700)
        hashes={}
        try:
            for name,content in sorted(files.items()):
                rel=Path(name)
                if rel.is_absolute() or not rel.parts or ".." in rel.parts or name=="manifest.json":raise ValueError("invalid generation path")
                if not isinstance(content,bytes):raise TypeError("generation files must be bytes")
                output=stage/rel; output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                self._private_directory(output.parent)
                digest=hashlib.sha256()
                fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
                with os.fdopen(fd,"wb") as stream:
                    view=memoryview(content)
                    for offset in range(0,len(view),65536):
                        block=view[offset:offset+65536]; stream.write(block); digest.update(block)
                    stream.flush(); os.fsync(stream.fileno())
                hashes[rel.as_posix()]=digest.hexdigest()
            manifest={"schema":1,"generation":generation_id,"files":hashes}
            raw=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()+b"\n"
            fd=os.open(stage/"manifest.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
            with os.fdopen(fd,"wb") as stream:stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            digest=self._manifest_digest(manifest)
            self.journal.checkpoint("registry-generation:"+generation_id,"stage_prepared",{"manifest_digest":digest,"previous":None})
            self._fsync_dir(stage)
            stage.rename(target); self._fsync_dir(self.root)
            self.journal.record_owned("generation",generation_id,"staged")
            self.journal.checkpoint("registry-generation:"+generation_id,"staged",{"manifest_digest":digest,"previous":None})
            return target
        except BaseException:
            shutil.rmtree(stage,ignore_errors=True)
            raise

    def _verified_manifest(self,generation_id:str)->tuple[Path,dict,str]:
        generation_id=self._validate_id(generation_id)
        target=self.root/generation_id
        if target.is_symlink() or not target.is_dir():raise GenerationError("generation is missing or symlinked")
        self._private_directory(target)
        manifest_path=target/"manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():raise GenerationError("manifest missing")
        self._private_file(manifest_path)
        try:manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError,ValueError):raise GenerationError("manifest invalid") from None
        if manifest.get("schema")!=1 or manifest.get("generation")!=generation_id or not isinstance(manifest.get("files"),dict):raise GenerationError("manifest identity mismatch")
        actual={}
        for path in target.rglob("*"):
            if path.is_symlink():raise GenerationError("generation contains a symlink")
            if path.is_dir():self._private_directory(path); continue
            if not path.is_file():raise GenerationError("generation contains a special file")
            if path==manifest_path:continue
            self._private_file(path)
            rel=path.relative_to(target).as_posix()
            digest=hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda:stream.read(65536),b""):digest.update(block)
            actual[rel]=digest.hexdigest()
        if actual!=manifest["files"]:raise GenerationError("generation content differs from manifest")
        manifest_digest=self._manifest_digest(manifest)
        if self.journal.owned("generation") is None:raise GenerationError("generation has no ownership ledger")
        op=self._operation(generation_id)
        if op is None or op.get("payload",{}).get("manifest_digest")!=manifest_digest:
            raise GenerationError("generation digest is not bound to installer journal")
        return target,manifest,manifest_digest

    def _read_pointer(self)->str|None:
        pointer=self.owned.path("active-generation")
        if not pointer.exists():
            return None
        if pointer.is_symlink():raise GenerationError("active pointer cannot be a symlink")
        self._private_file(pointer)
        value=pointer.read_text(encoding="utf-8").strip()
        value=self._validate_id(value)
        self._verified_manifest(value)
        return value

    def _write_pointer(self,generation_id:str|None):
        pointer=self.owned.path("active-generation")
        if pointer.exists() or pointer.is_symlink():
            if pointer.is_symlink():raise GenerationError("active pointer cannot be a symlink")
            self._private_file(pointer)
        if generation_id is None:
            pointer.unlink(missing_ok=True); self._fsync_dir(self.owned.root); return
        fd,name=tempfile.mkstemp(prefix=".active-generation-",dir=self.owned.root)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,"w",encoding="utf-8") as stream:
                stream.write(generation_id+"\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(name,pointer); self._fsync_dir(self.owned.root)
        finally:
            if os.path.exists(name):os.unlink(name)

    def activate(self,generation_id:str)->str|None:
        generation_id=self._validate_id(generation_id)
        _,_,digest=self._verified_manifest(generation_id)
        previous=self._read_pointer()
        self.journal.checkpoint("registry-generation:"+generation_id,"activation_prepared",{"manifest_digest":digest,"previous":previous})
        self._write_pointer(generation_id)
        self.journal.record_owned("generation",generation_id,"active")
        self.journal.checkpoint("registry-generation:"+generation_id,"active",{"manifest_digest":digest,"previous":previous})
        return previous

    def rollback(self,previous:str|None):
        current=self._read_pointer()
        operation=self._operation(current) if current else None
        if operation is None or operation.get("status") not in {"active","activation_prepared"}:
            raise GenerationError("active generation has no recoverable activation journal")
        expected=operation.get("payload",{}).get("previous")
        if previous!=expected:raise GenerationError("rollback target does not match recorded pre-activation pointer")
        if previous is not None:self._verified_manifest(self._validate_id(previous))
        self.journal.checkpoint("registry-generation:"+current,"rollback_prepared",{"manifest_digest":operation["payload"]["manifest_digest"],"previous":previous})
        self._write_pointer(previous)
        self.journal.record_owned("generation",current,"rolled_back")
        self.journal.checkpoint("registry-generation:"+current,"rolled_back",{"manifest_digest":operation["payload"]["manifest_digest"],"previous":previous})

    def recover_pointer_transaction(self)->str:
        """Reconcile a crash after pointer replace using the journaled intent."""
        pointer=self._read_pointer()
        for row in self.journal.owned("generation"):
            generation_id=row["resource_id"]
            op=self._operation(generation_id)
            if not op:continue
            if op.get("status")=="activation_prepared" and pointer==generation_id:
                _,_,digest=self._verified_manifest(generation_id)
                if digest!=op["payload"].get("manifest_digest"):raise GenerationError("activation intent digest mismatch")
                self.journal.record_owned("generation",generation_id,"active")
                self.journal.checkpoint("registry-generation:"+generation_id,"active",{"manifest_digest":digest,"previous":op["payload"].get("previous")})
                return "activation_reconciled"
            if op.get("status")=="rollback_prepared" and pointer==op["payload"].get("previous"):
                self.journal.record_owned("generation",generation_id,"rolled_back")
                self.journal.checkpoint("registry-generation:"+generation_id,"rolled_back",op["payload"])
                return "rollback_reconciled"
            if op.get("status") in {"activation_prepared","rollback_prepared"}:
                return "intent_pending_operator_review"
        return "clean"
