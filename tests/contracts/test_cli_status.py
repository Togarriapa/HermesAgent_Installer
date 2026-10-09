from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
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


    def test_interrupted_committed_wal_can_resume_and_recover_under_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = OwnedRoot(Path(temporary) / "state")
            root.ensure()
            lock_path = root.path("installer.lock")
            with process_lock(lock_path):
                pass
            database = root.path("journal.sqlite3")
            script = (
                "import os,sqlite3,sys; "
                "db=sqlite3.connect(sys.argv[1]); "
                "db.execute('PRAGMA journal_mode=WAL'); "
                "db.execute('CREATE TABLE operations (id TEXT PRIMARY KEY,status TEXT NOT NULL,updated_at REAL NOT NULL,payload TEXT NOT NULL)'); "
                "db.execute(\"INSERT INTO operations VALUES('installer:selection','interrupted',1,'{}')\"); "
                "db.commit(); os._exit(0)"
            )
            crashed = subprocess.run([sys.executable, "-c", script, str(database)], timeout=10)
            self.assertEqual(crashed.returncode, 0)
            wal = root.path("journal.sqlite3-wal")
            self.assertGreater(wal.stat().st_size, 0)
            from hermes_installer.cli import _resume_checkpoint_exists
            self.assertTrue(_resume_checkpoint_exists(root.root))
            self.assertIn("uncheckpointed", _recorded_component_findings(root.root)[0].message)
            with process_lock(lock_path):
                recovered = Journal(database).operation("installer:selection")
            self.assertIsNotNone(recovered)
            self.assertEqual(recovered["status"], "interrupted")

    def test_malformed_checkpoint_time_is_pending_not_an_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._state(Path(temporary) / "state").root
            with process_lock(root / "installer.lock"):
                db = sqlite3.connect(root / "journal.sqlite3")
                db.execute("UPDATE operations SET updated_at='not-a-time' WHERE id='installer:selection'")
                db.commit()
                db.close()
            findings = _recorded_component_findings(root)
            self.assertEqual(findings[0].state, OutcomeState.PENDING)
            self.assertIn("malformed", findings[0].message)



if __name__ == "__main__":
    unittest.main()
