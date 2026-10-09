"""Stdlib effect and tamper tests for immutable registry generations."""
import tempfile
import unittest
from pathlib import Path
from hermes_installer.registry.generation import GenerationError, GenerationStore
from hermes_installer.state import Journal, OwnedRoot

class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.owned = OwnedRoot(Path(self.temp.name) / "owned")
        self.owned.ensure()
        self.store = GenerationStore(self.owned, Journal(self.owned.path("journal.sqlite3")), mutation_locked=True)
    def tearDown(self): self.temp.cleanup()

    def test_activation_and_rollback_effects_preserve_both_generations(self):
        self.store.stage("one", {"runtime/config.json": b'{"v":1}'})
        self.assertIsNone(self.store.activate("one"))
        self.store.stage("two", {"runtime/config.json": b'{"v":2}'})
        self.assertEqual(self.store.activate("two"), "one")
        self.assertEqual(self.store._read_pointer(), "two")
        self.store.rollback("one")
        self.assertEqual(self.store._read_pointer(), "one")
        self.assertEqual((self.owned.root / "generations/two/runtime/config.json").read_bytes(), b'{"v":2}')

    def test_traversal_foreign_pointer_and_tamper_are_rejected(self):
        with self.assertRaises(ValueError): self.store.stage("bad", {"../outside": b"x"})
        self.store.stage("one", {"data": b"original"})
        pointer = self.owned.path("active-generation")
        pointer.write_text("../foreign\n"); pointer.chmod(0o600)
        with self.assertRaises((ValueError, GenerationError)): self.store.activate("one")
        pointer.unlink()
        self.store.activate("one")
        (self.owned.root / "generations/one/data").write_bytes(b"tampered")
        with self.assertRaises(GenerationError): self.store._read_pointer()
        with self.assertRaises(ValueError): self.store.rollback("../foreign")

    def test_unjournaled_manifest_shaped_directory_is_not_adopted(self):
        foreign = self.owned.path("generations/foreign")
        foreign.mkdir(mode=0o700); (foreign / "manifest.json").write_text('{"schema":1,"generation":"foreign","files":{}}'); (foreign / "manifest.json").chmod(0o600)
        with self.assertRaises(GenerationError): self.store.activate("foreign")

    def test_crash_after_pointer_swap_reconciles_from_journal_intent(self):
        self.store.stage("one", {"data": b"ok"})
        digest = self.store._verify("one")[2]
        payload = {"generation":"one","manifest_digest":digest,"previous":None,"previous_digest":None}
        self.store.journal.checkpoint("registry-active-pointer", "activation_prepared", payload)
        self.store._write_pointer("one")
        self.assertEqual(self.store.recover_pointer_transaction(), "activation_reconciled")
        self.assertEqual(self.store._read_pointer(), "one")

    def test_large_file_is_verified_as_stream_and_permissions_are_private(self):
        self.store.stage("one", {"assets/large.bin": b"z" * (2 * 1024 * 1024)})
        path = self.owned.root / "generations/one/assets/large.bin"
        self.assertEqual(path.stat().st_mode & 0o077, 0)
        self.assertEqual(self.store._verify("one")[2], self.store._digest(self.store._verify("one")[1]))

if __name__ == "__main__": unittest.main()
