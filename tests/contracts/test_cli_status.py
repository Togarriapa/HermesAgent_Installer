from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from hermes_installer.cli import _recorded_component_findings
from hermes_installer.state import Journal, OwnedRoot, process_lock
from hermes_installer.results import OutcomeState


class RecordedStatusTests(unittest.TestCase):
    def _state(self, path: Path):
        state_root = OwnedRoot(path)
        state_root.ensure()
        with process_lock(state_root.path("installer.lock")):
            Journal(state_root.path("journal.sqlite3")).checkpoint(
                "installer:selection", "bootstrap-complete", {
                    "config": {"components": {"hermes_agent": True}},
                    "report": {"agent_ready": True, "desktop_built": True},
                })
        return state_root

    @staticmethod
    def _snapshot(root: Path):
        return {
            p.name: (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns, p.stat().st_mode)
            for p in root.iterdir()
        }

    def test_status_is_immutable_historical_evidence_and_alias_matches_dots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._state(Path(temporary) / "state").root
            before = self._snapshot(root)
            findings = _recorded_component_findings(root, "hermes-agent")
            self.assertEqual(before, self._snapshot(root))
            self.assertEqual({item.code for item in findings}, {"hermes.agent.bootstrap"})
            self.assertTrue(all(item.state == OutcomeState.PENDING for item in findings))
            self.assertTrue(all(item.details["historical"] for item in findings))

    def test_nonempty_wal_is_indeterminate_without_touching_database_or_sidecars(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._state(Path(temporary) / "state").root
            db_path = root / "journal.sqlite3"
            db = sqlite3.connect(db_path)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_autocheckpoint=0")
            db.execute("INSERT INTO operations(id,status,updated_at,payload) VALUES('pending','active',1,'{}')")
            db.commit()
            wal = root / "journal.sqlite3-wal"
            self.assertGreater(wal.stat().st_size, 0)
            before = self._snapshot(root)
            findings = _recorded_component_findings(root)
            self.assertEqual(before, self._snapshot(root))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].state, OutcomeState.PENDING)
            self.assertIn("indeterminate", findings[0].message)
            db.close()

    def test_active_installer_lock_is_indeterminate_and_not_created_by_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._state(Path(temporary) / "state").root
            before = self._snapshot(root)
            with process_lock(root / "installer.lock"):
                findings = _recorded_component_findings(root)
            self.assertEqual(before, self._snapshot(root))
            self.assertEqual(findings[0].state, OutcomeState.PENDING)
            self.assertIn("active", findings[0].message)

    def test_missing_lock_and_foreign_marker_are_pending_without_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._state(Path(temporary) / "state").root
            (root / "installer.lock").unlink()
            before = self._snapshot(root)
            findings = _recorded_component_findings(root)
            self.assertEqual(before, self._snapshot(root))
            self.assertEqual(findings[0].state, OutcomeState.PENDING)
            (root / ".hermes-installer-owned").write_text("schema=other\n")
            self.assertEqual(_recorded_component_findings(root)[0].state, OutcomeState.PENDING)


if __name__ == "__main__":
    unittest.main()
