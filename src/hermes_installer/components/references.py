"""Searchable source catalogs keep attribution and provenance on every hit."""
from dataclasses import dataclass
from pathlib import Path
@dataclass(frozen=True,slots=True)
class Reference:
    source_id:str; path:str; title:str; body:str; origin:str
class ReferenceIndex:
    def __init__(self,source_id:str,origin:str,root:Path):
        self.source_id=source_id; self.origin=origin; self.root=root
    def search(self,query:str,limit:int=10)->tuple[Reference,...]:
        if not query.strip() or not 1<=limit<=50:raise ValueError("query required and limit must be 1..50")
        terms=query.casefold().split(); matches=[]
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.is_symlink():continue
            if path.suffix.lower() not in {".md",".yaml",".yml",".json",".txt"}:continue
            body=path.read_text(encoding="utf-8",errors="replace")
            score=sum(body.casefold().count(term) for term in terms)
            if score:matches.append((score,path,body))
        matches.sort(key=lambda row:(-row[0],row[1].as_posix()))
        return tuple(Reference(self.source_id,p.relative_to(self.root).as_posix(),p.stem,b[:4000],self.origin) for _,p,b in matches[:limit])
