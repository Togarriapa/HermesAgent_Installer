"""Native task-scoped skills, not global prompt concatenation."""
from pathlib import Path
from typing import Iterable
class SkillStore:
    def __init__(self,roots:Iterable[Path],project_roots:Iterable[Path]=()):
        self.roots=tuple(Path(p).resolve() for p in roots); self.project_roots=tuple(Path(p).resolve() for p in project_roots)
    def discover(self)->tuple[Path,...]:
        found={}
        for root in (*self.project_roots,*self.roots):
            if not root.is_dir():continue
            for skill in sorted(root.rglob("SKILL.md")):
                resolved=skill.resolve()
                if not any(resolved.is_relative_to(base) for base in (root,*self.roots,*self.project_roots)):continue
                found.setdefault(resolved.parent.name.casefold(),resolved.parent)
        return tuple(found.values())
    def load_for_task(self,task:str,selected:Iterable[str])->tuple[str,...]:
        chosen={name.casefold() for name in selected}; output=[]
        for folder in self.discover():
            if folder.name.casefold() not in chosen:continue
            skill=(folder/"SKILL.md").read_text(encoding="utf-8")
            output.append(skill)
        if not output and chosen:raise FileNotFoundError("selected skill not discoverable")
        return tuple(output)
