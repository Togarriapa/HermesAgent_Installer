"""R0063: ECC skills stay scoped and the selected hook needs an observable effect."""
from __future__ import annotations

import json
import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.ecc import (
    ecc_hook_status,
    discover_ecc_skills,
    invoke_codex_session_start_fixture,
    stage_ecc_skills_for_profile,
)
from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_handlers import review_host_hooks
from hermes_installer.components.skill_refs import audit_component_skill_file_map, audit_skill_file_map
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


class EccAdapterTests(unittest.TestCase):
    @staticmethod
    def _verified_source(files):
        contract = resolve_component_adapter("ecc")
        modes = {name: 0o644 for name in files}
        content = hashlib.sha256()
        for name in sorted(files):
            content.update(name.encode() + b"\0")
            content.update(f"{modes[name]:o}".encode() + b"\0")
            content.update(hashlib.sha256(files[name]).digest())
        tree, _ = _git_tree(files, modes)
        archive = "a" * 64
        provenance = {
            "schema": 1, "component_id": "ecc",
            "source_identity": contract.source_identity,
            "source_url": contract.selected_source_url,
            "revision": contract.revision,
            "source_selection": contract.source_selection,
            "source_archive_sha256": archive,
            "source_content_sha256": content.hexdigest(),
            "source_tree_sha": tree,
            "declared_license": contract.license,
            "license_files": ["LICENSE"],
            "redistribution_license_review_required": contract.redistribution_license_review_required,
        }
        complete = dict(files)
        complete["INSTALLER-SOURCE-PROVENANCE.json"] = (
            json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        modes["INSTALLER-SOURCE-PROVENANCE.json"] = 0o644
        return VerifiedComponentSource(
            component_id="ecc", source_identity=contract.source_identity,
            revision=contract.revision, files=complete, file_modes=modes,
            archive_sha256=archive, content_sha256=content.hexdigest(),
            source_tree_sha=tree, license=contract.license, license_files=("LICENSE",),
            redistribution_license_review_required=contract.redistribution_license_review_required,
        )

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

    def test_full_source_audit_quarantines_all_broken_roots_without_dropping_source(self):
        files = {
            "skills/broken/SKILL.md": b"---\nname: broken\ndescription: Broken.\n---\nSee [missing](missing.md).\n",
            "helper.py": b"# retained pinned source\n",
        }
        result = audit_component_skill_file_map(
            "ecc", "ef648e01899ba3e8dc6371642deaaf64b4477775", files,
        )
        self.assertTrue(result.complete)
        self.assertEqual((), result.skill_files)
        self.assertIn("skills/broken/SKILL.md", dict(result.quarantined_skill_problems))
        self.assertIn("helper.py", files)

    def test_hook_inventory_is_inert_and_does_not_enable_callbacks(self):
        review = review_host_hooks("ecc", {"hooks/hooks.json": b'{"hooks":{}}'})
        self.assertFalse(review.may_install)
        self.assertEqual("review-required", review.status)
        available, reason = ecc_hook_status()
        self.assertFalse(available)
        self.assertIn("unavailable", reason)

    def test_stages_only_selected_valid_skill_closure_and_retains_full_source(self):
        source = self._verified_source({
            "LICENSE": b"private fixture license\n",
            "skills/clean/SKILL.md": b"---\nname: clean\ndescription: Works.\n---\nSee [guide](guide.md).\n",
            "skills/clean/guide.md": b"Use the owned local fixture.\n",
            "skills/broken/SKILL.md": b"---\nname: broken\ndescription: Broken.\n---\nSee [missing](missing.md).\n",
        })
        root = Path(tempfile.mkdtemp()).resolve() / "profile-data"
        owned = OwnedRoot(root)
        owned.ensure()
        with process_lock(owned.path("installer.lock")):
            store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
            binding = stage_ecc_skills_for_profile(
                source, store, profile_id="fixture-profile", profile_data_root=root,
            )
            complete_source, _manifest, _digest = store._verify(source.generation_id)
            self.assertTrue((complete_source / "skills/broken/SKILL.md").is_file())
            self.assertEqual(("skills/clean/SKILL.md",), binding.skill_files)
            self.assertEqual(b"Use the owned local fixture.\n", (binding.external_dir / "skills/clean/guide.md").read_bytes())
            self.assertFalse((binding.external_dir / "skills/broken/SKILL.md").exists())
            selection = json.loads((binding.external_dir / "INSTALLER-ECC-SKILL-SELECTION.json").read_text())
            self.assertEqual(["skills/clean/SKILL.md"], selection["selected_skill_files"])
            self.assertEqual("skills/broken/SKILL.md", selection["quarantined_skill_problems"][0]["skill_file"])

    def test_staging_rejects_explicit_quarantined_skill(self):
        source = self._verified_source({
            "LICENSE": b"private fixture license\n",
            "skills/broken/SKILL.md": b"---\nname: broken\ndescription: Broken.\n---\nSee [missing](missing.md).\n",
        })
        root = Path(tempfile.mkdtemp()).resolve() / "profile-data"
        owned = OwnedRoot(root)
        owned.ensure()
        with process_lock(owned.path("installer.lock")):
            store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
            with self.assertRaisesRegex(ValueError, "complete eligible pinned skill roots"):
                stage_ecc_skills_for_profile(
                    source, store, profile_id="fixture-profile", profile_data_root=root,
                    selected_skill_files=("skills/broken/SKILL.md",),
                )

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
