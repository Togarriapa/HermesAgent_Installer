"""Generation store ownership, crash recovery and data preservation tests."""
import tempfile, unittest
from pathlib import Path
from hermes_installer.registry.generation import GenerationError, GenerationStore
from hermes_installer.state import Journal, OwnedRoot

class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.owned=OwnedRoot(Path(self.temp.name)/"installer")
        self.owned.ensure()
        self.store=GenerationStore(self.owned,Journal(self.owned.path("installer-state.sqlite3")),mutation_locked=True)
    def tearDown(self): self.temp.cleanup()
    def test_activation_rollback_preserve_immutable_generations(self):
        self.store.stage("one",{"runtime/settings.json":b'{"v":1}'})
        self.assertIsNone(self.store.activate("one"))
        self.store.stage("two",{"runtime/settings.json":b'{"v":2}'})
        self.assertEqual(self.store.activate("two"),"one")
        self.assertEqual(self.store._read_pointer(),"two")
        self.store.rollback("one")
        self.assertEqual(self.store._read_pointer(),"one")
        self.assertEqual((self.owned.root/"generations/two/runtime/settings.json").read_bytes(),b'{"v":2}')
    def test_foreign_pointer_traversal_and_tamper_are_denied(self):
        self.store.stage("one",{"data":b"original"})
        pointer=self.owned.path("active-generation"); pointer.write_text("../outside\\n"); pointer.chmod(0o600)
        with self.assertRaises((ValueError,GenerationError)): self.store.activate("one")
        pointer.unlink()
        with self.assertRaises(ValueError): self.store.activate("../outside")
        self.store.activate("one")
        (self.owned.root/"generations/one/data").write_bytes(b"tampered")
        with self.assertRaises(GenerationError): self.store._read_pointer()
    def test_unjournaled_manifest_shaped_generation_is_not_adopted(self):
        foreign=self.owned.path("generations/foreign"); foreign.mkdir(mode=0o700)
        manifest=foreign/"manifest.json"; manifest.write_text('{"schema":1,"generation":"foreign","files":{}}'); manifest.chmod(0o600)
        with self.assertRaises(GenerationError): self.store.activate("foreign")
    def test_reconcile_after_atomic_pointer_swap(self):
        self.store.stage("one",{"data":b"ok"})
        digest=self.store._verify("one")[2]
        intent={"generation":"one","manifest_digest":digest,"previous":None,"previous_digest":None}
        self.store.journal.checkpoint("registry-active-pointer","activation_prepared",intent)
        self.store._write_pointer("one")
        self.assertEqual(self.store.recover_pointer_transaction(),"activation_reconciled")
        self.assertEqual(self.store._read_pointer(),"one")
    def test_source_modes_are_preserved_as_private_non_executable_data(self):
        path=self.store.stage("source",{"helper.sh":b"#!/bin/sh\\n"},file_modes={"helper.sh":0o755})
        self.assertEqual((path/"helper.sh").stat().st_mode&0o777,0o500)
        self.store._verify("source")
    def test_large_asset_is_stream_verified_private_and_immutable(self):
        self.store.stage("one",{"assets/large.bin":b"x"*(2*1024*1024)})
        path=self.owned.root/"generations/one/assets/large.bin"
        self.assertEqual(path.stat().st_mode&0o077,0)
        self.assertEqual(self.store._verify("one")[2],self.store._digest(self.store._verify("one")[1]))
if __name__=="__main__": unittest.main()
