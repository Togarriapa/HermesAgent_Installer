import json,os,tempfile,shutil
from pathlib import Path
class GenerationError(RuntimeError):pass
class GenerationStore:
    def __init__(self,root:Path):self.root=root; root.mkdir(parents=True,exist_ok=True)
    def stage(self,generation_id:str,files:dict[str,bytes])->Path:
        if not generation_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in generation_id):raise ValueError("invalid generation id")
        target=self.root/generation_id
        if target.exists():raise GenerationError("generation is immutable")
        tmp=Path(tempfile.mkdtemp(prefix=".stage-",dir=self.root))
        try:
            for name,data in files.items():
                rel=Path(name)
                if rel.is_absolute() or ".." in rel.parts:raise ValueError("generation path escapes root")
                out=tmp/rel; out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(data)
            (tmp/"manifest.json").write_text(json.dumps({"generation":generation_id,"files":sorted(files)},sort_keys=True)+"\n")
            tmp.rename(target); return target
        except BaseException:shutil.rmtree(tmp,ignore_errors=True); raise
    def activate(self,generation_id:str)->str|None:
        target=self.root/generation_id
        if not (target/"manifest.json").is_file():raise GenerationError("generation incomplete")
        active=self.root/"active"; old=active.read_text().strip() if active.is_file() else None
        fd,tmp=tempfile.mkstemp(prefix=".active-",dir=self.root)
        try:
            with os.fdopen(fd,"w") as f:f.write(generation_id+"\n"); f.flush(); os.fsync(f.fileno())
            os.replace(tmp,active)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
        return old
    def rollback(self,previous:str|None):
        if previous is None:(self.root/"active").unlink(missing_ok=True)
        else:self.activate(previous)
