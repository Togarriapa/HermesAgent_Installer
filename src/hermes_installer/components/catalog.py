import hashlib,shutil,tempfile
from dataclasses import dataclass
from pathlib import Path,PurePosixPath
from typing import Iterable
@dataclass(frozen=True,slots=True)
class ComponentSpec:
    id:str; source_url:str; revision:str; aliases:tuple[str,...]=(); kind:str="skill"; license:str|None=None; mode:str="on_demand"; executable_hooks:tuple[str,...]=()
@dataclass(frozen=True,slots=True)
class ImportedSkill:
    component_id:str; destination:Path; files:tuple[str,...]; sha256:str; discoverable:bool; hook_status:str
class ComponentCatalog:
    def __init__(self,specs:Iterable[ComponentSpec]):
        specs=tuple(specs); self.by_name={}; self.by_id={s.id:s for s in specs}
        for spec in specs:
            for alias in (spec.id,*spec.aliases):
                key=alias.casefold(); old=self.by_name.get(key)
                if old and old.id!=spec.id:raise ValueError(f"alias collision: {alias}")
                self.by_name[key]=spec
    def resolve(self,name):
        try:return self.by_name[name.casefold()]
        except KeyError as exc:raise KeyError(f"unknown component {name!r}; provide explicit source override") from exc
    @staticmethod
    def manifest(root:Path):
        names=[]; h=hashlib.sha256()
        for path in sorted(root.rglob("*")):
            rel=path.relative_to(root).as_posix()
            if path.is_symlink():raise ValueError(f"symlink not allowed: {rel}")
            if path.is_file():
                if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts:raise ValueError("path escape")
                names.append(rel); h.update(rel.encode()+b"\0")
                with path.open("rb") as stream:
                    for block in iter(lambda:stream.read(65536),b""):h.update(block)
        return tuple(names),h.hexdigest()
    def import_skill(self,name:str,source:Path,destination_root:Path)->ImportedSkill:
        spec=self.resolve(name)
        if spec.kind not in {"skill","instruction_collection","reference"}:raise ValueError("component is not a skill tree")
        source=source.resolve(strict=True); files,digest=self.manifest(source)
        if not files:raise ValueError("empty source tree")
        destination_root.mkdir(parents=True,exist_ok=True); target=destination_root/spec.id; stage=Path(tempfile.mkdtemp(prefix="."+spec.id+"-",dir=destination_root)); old=None
        try:
            for rel in files:
                src=source/rel; out=stage/rel; out.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(src,out); out.chmod(0o555 if src.suffix in {".py",".sh",".js",".mjs"} else 0o444)
            if target.exists():
                old=destination_root/("."+spec.id+".previous")
                if old.exists():shutil.rmtree(old)
                target.rename(old)
            stage.rename(target)
            if old:shutil.rmtree(old)
            return ImportedSkill(spec.id,target,files,digest,True,"pending_hook_verification" if spec.executable_hooks else "instruction_only")
        except BaseException:
            shutil.rmtree(stage,ignore_errors=True)
            if old and old.exists() and not target.exists():old.rename(target)
            raise
    def application_gate(self,name:str,requested:set[str],granted:set[str]):
        spec=self.resolve(name)
        if spec.kind!="application":return False,"not an application"
        denied=sorted(requested-granted)
        if denied:return False,"missing grants: "+", ".join(denied)
        if spec.mode!="on_demand":return False,"application must remain on demand"
        return True,"ready for isolated launch; dependencies and ARM64 remain unverified"
