"""Root memory state resolver custody and per-profile journal contracts."""
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.memory.owner_ledger import OwnerTransitionError, SQLiteOwnerLedger
from hermes_installer.memory.root_state import (
    MemoryAuthorityStateDirectory, MemoryStateDenied, RootJournalSelection,
    resolve_memory_state_directory,
)


class MemoryRootStateTests(unittest.TestCase):
    def _selection(self, root: Path):
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        # Keep test paths beneath the checkout so macOS /tmp and /var aliases
        # do not weaken the production no-symlink walk.
        return RootJournalSelection("authority-journal-main", root.resolve())

    def test_only_protected_state_root_id_resolves_to_profile_hash_directory(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temporary:
            root = self._selection(Path(temporary) / "journal")
            enrollment = SimpleNamespace(
                authority_state_root_id=root.root_id, profile_id="profile-a",
                data_root_id="service-data-a")
            state = resolve_memory_state_directory(
                enrollment, {root.root_id: root}, expected_uid=os.geteuid())
            try:
                expected = hashlib.sha256(b"profile-a").hexdigest()
                self.assertEqual(state.profile_key, expected)
                self.assertTrue(state.path("owner-ledger.sqlite3").parent.exists())
                owner = SQLiteOwnerLedger(state)
                self.assertEqual(owner.get_owner_state("profile-a"), (None, 0))
                with self.assertRaisesRegex(OwnerTransitionError, "another profile"):
                    owner.set_owner("profile-b", "agentmemory")
                db_path = state.path("owner-ledger.sqlite3")
                info = db_path.stat()
                self.assertEqual(info.st_uid, os.geteuid())
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            finally:
                state.close()

    def test_unknown_state_id_data_root_alias_symlink_and_permissive_directory_deny(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temporary:
            root = self._selection(Path(temporary) / "journal")
            good = SimpleNamespace(authority_state_root_id=root.root_id,
                                   profile_id="profile-a", data_root_id="data-a")
            with self.assertRaises(MemoryStateDenied):
                resolve_memory_state_directory(good, {}, expected_uid=os.geteuid())
            aliased = SimpleNamespace(authority_state_root_id="same-id",
                                      profile_id="profile-a", data_root_id="same-id")
            with self.assertRaises(MemoryStateDenied):
                resolve_memory_state_directory(aliased,
                    {"same-id": RootJournalSelection("same-id", root.path)},
                    expected_uid=os.geteuid())

            linked_root = Path(temporary) / "linked"
            linked_root.symlink_to(root.path, target_is_directory=True)
            linked = RootJournalSelection("linked-root", linked_root)
            with self.assertRaises(MemoryStateDenied):
                MemoryAuthorityStateDirectory(linked, "profile-a", expected_uid=os.geteuid())

            state = resolve_memory_state_directory(good, {root.root_id: root},
                                                   expected_uid=os.geteuid())
            try:
                state.root.chmod(0o750)
                with self.assertRaises(MemoryStateDenied):
                    state.ensure()
            finally:
                state.root.chmod(0o700)
                state.close()


if __name__ == "__main__":
    unittest.main()
