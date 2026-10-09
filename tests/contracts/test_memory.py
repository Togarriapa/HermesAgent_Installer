"""Memory defaults stay unavailable until durable and trusted adapters exist."""
import unittest
from hermes_installer.memory import MemoryManager,MemoryRecord,MemoryUnavailable

class Store:
    name="store"
    def capture(self,record): raise AssertionError("must not write")
    def search(self,namespace,query,limit): raise AssertionError("must not search")
    def export(self,namespace): raise AssertionError("must not export")
    def remove(self,namespace,record_id): raise AssertionError("must not delete")

class MemoryTests(unittest.TestCase):
    def test_legacy_source_string_and_volatile_owner_never_authorize_memory(self):
        manager=MemoryManager([Store()],lambda *_:(True,""))
        with self.assertRaises(MemoryUnavailable): manager.select_owner("profile","store")
        with self.assertRaises(MemoryUnavailable): manager.ingest(MemoryRecord("id","ns","profile","trusted-looking","private"))
        with self.assertRaises(MemoryUnavailable): manager.search("store","ns","query")
        with self.assertRaises(MemoryUnavailable): manager.export("store","ns")
        with self.assertRaises(MemoryUnavailable): manager.remove("store","ns","id")


class OwnerProvider:
    def __init__(self,name,events):
        self.name,self.events=name,events
    def flush(self,profile): self.events.append((self.name,"flush",profile))
    def stop_capture(self,profile): self.events.append((self.name,"stop",profile))
    def start_capture(self,profile,context=None): self.events.append((self.name,"start",profile))


class RevocationQueue:
    def __init__(self,ledger,events):
        self.ledger,self.events=ledger,events
    def revoke_owner(self,profile,provider,generation,*,reason):
        self.events.append(("revoke",provider,generation,self.ledger.get_owner(profile),reason))


class OwnerTransitionTests(unittest.TestCase):
    def test_owner_change_stops_old_commits_epoch_then_revokes_old_queue(self):
        import tempfile
        from pathlib import Path
        from hermes_installer.memory.owner_ledger import SQLiteOwnerLedger
        events=[]
        context=type("Context",(),{"profile_id":"p1","namespace_id":"n1"})()
        with tempfile.TemporaryDirectory() as directory:
            ledger=SQLiteOwnerLedger(Path(directory)/"ledger")
            ledger.set_owner("p1","first")
            providers=[OwnerProvider("first",events),OwnerProvider("second",events)]
            queue=RevocationQueue(ledger,events)
            manager=MemoryManager(providers,owner_ledger=ledger,
                trusted_authorizer=lambda *_:(True,""),capture_queue=queue)
            manager.select_owner("p1","second",context=context)
            self.assertEqual(ledger.get_owner_state("p1"),("second",2))
            self.assertEqual(events[-1],("revoke","first",1,"second","owner_changed"))
            self.assertIn(("first","stop","p1"),events)
            self.assertIn(("second","start","p1"),events)

if __name__=="__main__": unittest.main()
