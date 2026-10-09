from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hermes_installer.cli import _recorded_component_findings
from hermes_installer.state import Journal, OwnedRoot
from hermes_installer.results import OutcomeState


class RecordedStatusTests(unittest.TestCase):
    def test_reads_component_state_without_creating_or_mutating_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_root = OwnedRoot(Path(temporary) / "state")
            state_root.ensure()
            journal = Journal(state_root.path("journal.sqlite3"))
            journal.checkpoint("installer:selection", "bootstrap-complete", {
                "config": {"components": {"hermes_agent": True}},
                "report": {"agent_ready": True, "desktop_built": False},
            })
            journal.record_owned("provider_gateway", "loopback-gateway", "active")
            db = state_root.path("journal.sqlite3")
            before = (db.stat().st_size, db.stat().st_mtime_ns, {p.name for p in state_root.root.iterdir()})
            findings = _recorded_component_findings(state_root.root)
            after = (db.stat().st_size, db.stat().st_mtime_ns, {p.name for p in state_root.root.iterdir()})
            self.assertEqual(before, after)
            states = {item.code: item.state for item in findings}
            self.assertEqual(states["hermes.agent.bootstrap"], OutcomeState.READY)
            self.assertEqual(states["hermes.desktop.build"], OutcomeState.PENDING)
            gateway = next(item for item in findings if item.code == "resource.provider_gateway")
            self.assertEqual(gateway.state, OutcomeState.READY)
            self.assertEqual(gateway.details, {"count": 1})

    def test_unknown_component_is_pending_and_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_root = OwnedRoot(Path(temporary) / "state")
            state_root.ensure()
            Journal(state_root.path("journal.sqlite3")).checkpoint(
                "installer:selection", "active", {"config": {}, "report": {}})
            before = {p.name for p in state_root.root.iterdir()}
            findings = _recorded_component_findings(state_root.root, "mcp")
            after = {p.name for p in state_root.root.iterdir()}
            self.assertEqual(before, after)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].state, OutcomeState.PENDING)


if __name__ == "__main__":
    unittest.main()
