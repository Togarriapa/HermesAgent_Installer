from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.state import Journal, OwnedRoot, OwnershipError, process_lock


class StateContractTests(unittest.TestCase):
    def test_journal_recovers_checkpoint_and_tracks_only_owned_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = OwnedRoot(root / "state")
            state_root.ensure()
            journal = Journal(state_root.path("journal.sqlite3"))
            journal.checkpoint("install", "downloaded", {"revision": "abc123"})
            journal.record_owned("service", "hermes-agent.service")
            self.assertEqual(journal.operation("install")["payload"]["revision"], "abc123")
            self.assertEqual(journal.owned(), [{"kind": "service", "resource_id": "hermes-agent.service", "created_at": unittest.mock.ANY, "state": "active"}])

    def test_owned_root_rejects_traversal_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            managed = OwnedRoot(base / "managed")
            managed.ensure()
            with self.assertRaises(OwnershipError):
                managed.path("../outside")
            target = base / "outside"
            target.mkdir()
            (base / "managed" / "escape").symlink_to(target, target_is_directory=True)
            with self.assertRaises(OwnershipError):
                managed.path("escape/file")

    def test_owned_root_refuses_broad_and_unowned_nonempty_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with self.assertRaises(OwnershipError):
                OwnedRoot(Path("/")).ensure()
            unowned = base / "existing"
            unowned.mkdir()
            (unowned / "keep.txt").write_text("user data")
            with self.assertRaises(OwnershipError):
                OwnedRoot(unowned).ensure()
            owned_child = OwnedRoot(base / "installer-owned" / "state")
            owned_child.ensure()
            self.assertTrue(owned_child.path(".hermes-installer-owned").exists())

    def test_process_lock_denies_duplicate_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            owned_root = OwnedRoot(Path(temporary) / "state")
            owned_root.ensure()
            lock = owned_root.path("installer.lock")
            with process_lock(lock):
                with self.assertRaises(RuntimeError):
                    with process_lock(lock):
                        pass


if __name__ == "__main__":
    unittest.main()
