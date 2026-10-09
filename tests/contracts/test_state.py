from __future__ import annotations

import sys
import tempfile
import unittest
from unittest import mock
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
            self.assertEqual(journal.owned(), [{"kind": "service", "resource_id": "hermes-agent.service", "created_at": mock.ANY, "state": "active"}])

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

    def test_marker_and_lock_must_be_private_owned_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owned = OwnedRoot(base / "owned")
            owned.ensure()
            marker = base / "owned" / ".hermes-installer-owned"
            marker.chmod(0o644)
            with self.assertRaises(OwnershipError):
                OwnedRoot(base / "owned").ensure()
            marker.write_text("foreign marker")
            marker.chmod(0o600)
            with self.assertRaises(OwnershipError):
                OwnedRoot(base / "owned").ensure()

    def test_process_lock_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owned = OwnedRoot(base / "owned")
            owned.ensure()
            external = base / "outside"
            external.write_text("preserve")
            (base / "owned" / "installer.lock").symlink_to(external)
            with self.assertRaises(OwnershipError):
                with process_lock(owned.path("installer.lock")):
                    self.fail("symlink lock must never be followed")

    def test_process_lock_denies_duplicate_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            owned_root = OwnedRoot(Path(temporary) / "state")
            owned_root.ensure()
            lock = owned_root.path("installer.lock")
            with process_lock(lock):
                with self.assertRaises(RuntimeError):
                    with process_lock(lock):
                        pass

    def test_journal_events_are_append_only_and_redact_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = OwnedRoot(Path(temporary) / "state")
            root.ensure()
            journal = Journal(root.path("journal.sqlite3"))
            journal.checkpoint("install", "failed:products", {"api_token": "sensitive", "credential_ref": "keyring://hermes"})
            journal.event("install", "products", "failed", {"exit_code": 1, "authorization": "Bearer sensitive", "error": "token=secret-value"})
            journal.event("install", "products", "retry", {"exit_code": 0})
            self.assertEqual(journal.operation("install")["payload"]["api_token"], "[REDACTED]")
            self.assertEqual(journal.operation("install")["payload"]["credential_ref"], "keyring://hermes")
            events = journal.events("install")
            self.assertEqual([event["event"] for event in events], ["failed", "retry"])
            self.assertEqual(events[0]["details"]["authorization"], "[REDACTED]")
            self.assertNotIn("secret-value", events[0]["details"]["error"])


if __name__ == "__main__":
    unittest.main()
