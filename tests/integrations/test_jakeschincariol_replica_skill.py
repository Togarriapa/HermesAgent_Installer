"""R0064: complete skill/helper discovery and a harmless local parity fixture."""
from __future__ import annotations

import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.jakeschincariol_replica_skill import (
    discover_replica_skill,
    run_replica_parity_fixture,
)
from hermes_installer.components.skill_handlers import SkillAdapterError


_SKILLS = (
    "replica-architect", "replica-backend", "replica-brand", "replica-build",
    "replica-deploy", "replica-design", "replica-diff", "replica-entrepreneur",
    "replica-launch", "replica-recon", "replica-test",
)


def _write_source(root: Path, *, with_helper: bool = True) -> None:
    for name in _SKILLS:
        folder = root / name
        folder.mkdir(parents=True)
        if name == "replica-diff":
            body = (
                "---\nname: replica-diff\ndescription: Compare a local synthetic feature matrix.\n---\n"
                "Run the documented fixture:\n\n```bash\npython3 parity.py features.csv\n```\n"
            )
        else:
            body = f"---\nname: {name}\ndescription: Synthetic fixture skill.\n---\n"
        (folder / "SKILL.md").write_text(body, encoding="utf-8")
    if with_helper:
        helper = root / "replica-diff" / "parity.py"
        helper.write_text(
            "import csv,sys\n"
            "with open(sys.argv[1], newline='', encoding='utf-8') as stream:\n"
            " rows=list(csv.DictReader(stream))\n"
            "score=100.0 if rows and all(row['clone']=='yes' for row in rows) else 0.0\n"
            "print(f'Parity: {score:.1f} / 100')\n"
            "print('features 100.0  (1 counted, must-haves 1 of 1 done)')\n",
            encoding="utf-8",
        )
    files = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*") if path.is_file()
    }
    from hermes_installer.registry.source import _git_tree
    tree_sha, _ = _git_tree(files, {name: 0o644 for name in files})
    (root / "INSTALLER-SOURCE-PROVENANCE.json").write_text(json.dumps({
        "component_id": "jakeschincariol-replica-skill",
        "source_identity": "Jakeschincariol/replica-skill",
        "revision": "77c9436fb3d18c3d58169efb8caf4fe906b0dc51",
        "source_tree_sha": tree_sha,
    }), encoding="utf-8")


class ReplicaSkillAdapterTests(unittest.TestCase):
    def test_all_skill_directories_and_documented_helper_references_resolve(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            _write_source(root)
            files = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*") if path.is_file()
            }
            result = discover_replica_skill(files)
            self.assertEqual(11, len(result.skills))
            self.assertEqual(1, len(result.helper_references))
            self.assertEqual("replica-diff/parity.py", result.helper_references[0].source_path)
            self.assertTrue(result.discovery.reference_audit.complete)
            self.assertEqual("77c9436fb3d18c3d58169efb8caf4fe906b0dc51", result.revision)

    def test_documented_local_helper_runs_only_on_synthetic_temporary_workspace(self):
        python = shutil.which("python3")
        if not python:
            self.skipTest("Python 3 is required to invoke the selected helper fixture")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            workspace = base / "workspace"
            source.mkdir()
            workspace.mkdir()
            _write_source(source)
            with (workspace / "features.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(("feature", "area", "priority", "original", "clone", "notes"))
                writer.writerow(("synthetic local flow", "fixture", "must", "yes", "yes", ""))
            proof = run_replica_parity_fixture(source, workspace, python_executable=Path(python))
            self.assertEqual("replica-diff/parity.py", proof.helper)
            self.assertEqual(100.0, proof.score)
            self.assertIn("Parity: 100.0 / 100", proof.stdout)
            self.assertFalse(list(workspace.glob("**/.git")))

    def test_missing_documented_helper_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            _write_source(root, with_helper=False)
            files = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*") if path.is_file()
            }
            with self.assertRaisesRegex(SkillAdapterError, "documented helper is missing"):
                discover_replica_skill(files)


if __name__ == "__main__":
    unittest.main()
