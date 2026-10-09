"""R0063: ECC skills stay scoped and the selected hook needs an observable effect."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.ecc import (
    ecc_hook_status,
    discover_ecc_skills,
    invoke_codex_session_start_fixture,
)
from hermes_installer.components.skill_handlers import review_host_hooks
from hermes_installer.components.skill_refs import audit_skill_file_map


class EccAdapterTests(unittest.TestCase):
    def test_aliases_resolve_to_one_component_and_broken_skills_are_reported(self):
        from hermes_installer.components.adapters import resolve_component_adapter

        self.assertEqual("ecc", resolve_component_adapter("affaan-m/ECC").component_id)
        self.assertEqual("ecc", resolve_component_adapter("ecc").component_id)
        files = {
            "skills/clean/SKILL.md": b"---\nname: clean\ndescription: Works.\n---\nSee [guide](guide.md).\n",
            "skills/clean/guide.md": b"Use the local fixture only.\n",
            "skills/broken/SKILL.md": b"---\nname: broken\ndescription: Broken.\n---\nSee [missing](missing.md).\n",
        }
        result = discover_ecc_skills(files)
        self.assertEqual(("skills/clean/SKILL.md",), result.eligible_skill_files)
        self.assertEqual("skills/broken/SKILL.md", result.excluded_skill_problems[0][0])
        self.assertIn("missing.md", result.excluded_skill_problems[0][1][0])
        self.assertFalse(result.reference_audit.complete)

    def test_hook_inventory_is_inert_and_does_not_enable_callbacks(self):
        review = review_host_hooks("ecc", {"hooks/hooks.json": b'{"hooks":{}}'})
        self.assertFalse(review.may_install)
        self.assertEqual("review-required", review.status)
        available, reason = ecc_hook_status()
        self.assertFalse(available)
        self.assertIn("unavailable", reason)

    def test_selected_codex_session_start_invokes_callback_inside_temp_coding_fixture(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is required to invoke the selected ECC hook fixture")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            project = base / "coding-project"
            home = base / "home"
            (source / "hooks").mkdir(parents=True)
            (source / "scripts" / "hooks").mkdir(parents=True)
            project.mkdir()
            home.mkdir()
            (source / "hooks" / "codex-hooks.json").write_text(json.dumps({
                "hooks": {"SessionStart": [{"matcher": ".*", "hooks": [{
                    "type": "command",
                    "command": 'node scripts/hooks/session-start-bootstrap.js',
                }]}]}
            }), encoding="utf-8")
            (source / "scripts" / "hooks" / "session-start-bootstrap.js").write_text(
                "const fs=require('fs'),path=require('path');"
                "let raw='';process.stdin.on('data',x=>raw+=x);"
                "process.stdin.on('end',()=>{const e=JSON.parse(raw);"
                "const d=path.join(e.cwd,'.observer-sessions');fs.mkdirSync(d,{recursive:true});"
                "fs.writeFileSync(path.join(d,e.session_id+'.json'),JSON.stringify({"
                "sessionId:e.session_id,hook:e.hook_event_name,cwd:process.cwd()}));});\n",
                encoding="utf-8",
            )
            provenance_files = {}
            provenance_modes = {}
            for path in source.rglob("*"):
                if path.is_file():
                    relative = path.relative_to(source).as_posix()
                    provenance_files[relative] = path.read_bytes()
                    provenance_modes[relative] = 0o644
            from hermes_installer.registry.source import _git_tree
            tree_sha, _ = _git_tree(provenance_files, provenance_modes)
            (source / "INSTALLER-SOURCE-PROVENANCE.json").write_text(json.dumps({
                "component_id": "ecc",
                "source_identity": "affaan-m/ECC",
                "revision": "ef648e01899ba3e8dc6371642deaaf64b4477775",
                "source_tree_sha": tree_sha,
            }), encoding="utf-8")

            # Recompute after provenance is added; the source pin tree excludes
            # the installer-owned provenance file.
            proof = invoke_codex_session_start_fixture(
                source, project, home, node_executable=Path(node), session_id="R0063-session"
            )
            self.assertEqual("SessionStart", proof.event)
            self.assertTrue((project / proof.callback_path).is_file())
            lease = json.loads((project / proof.callback_path).read_text(encoding="utf-8"))
            self.assertEqual("R0063-session", lease["sessionId"])
            self.assertEqual(project.resolve(), Path(lease["cwd"]).resolve())
            available, reason = ecc_hook_status(fixture_proof=proof)
            self.assertFalse(available)
            self.assertIn("native host registration", reason)


if __name__ == "__main__":
    unittest.main()
