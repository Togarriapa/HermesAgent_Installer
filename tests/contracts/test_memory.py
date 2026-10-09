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
if __name__=="__main__": unittest.main()
