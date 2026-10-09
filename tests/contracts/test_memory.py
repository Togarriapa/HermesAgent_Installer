from hermes_installer.memory import MemoryManager,MemoryRecord
class Store:
    name="store"
    def __init__(self):self.records=[]
    def capture(self,r):self.records.append(r)
    def search(self,ns,q,n):return self.records[:n]
    def export(self,ns):return [r for r in self.records if r.namespace==ns]
    def remove(self,ns,rid):
        old=len(self.records); self.records=[r for r in self.records if not (r.namespace==ns and r.id==rid)]; return len(self.records)<old
def test_memory_single_owner_scope_policy_and_no_recursion():
    provider=Store(); manager=MemoryManager([provider],lambda _,kind:(kind!="memory_extraction","private route denied"))
    manager.select_owner("profile-a","store")
    rec=MemoryRecord("one","user-a/profile-a","profile-a","conversation","fact")
    manager.ingest(rec); assert manager.search("store",rec.namespace,"fact")==[rec]
    with pytest.raises(PermissionError):manager.ingest(MemoryRecord("x","n","profile-a","memory:one","recursive"))
    assert manager.search("store","other","fact")==[]
    blocked=MemoryManager([provider],lambda *_:(False,"ineligible"))
    blocked.select_owner("profile-a","store")
    with pytest.raises(PermissionError):blocked.ingest(rec)
import pytest
