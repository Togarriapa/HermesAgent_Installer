"""Pending adapters fail closed instead of claiming runtime completion."""
import tempfile
import unittest
import json
from pathlib import Path
from hermes_installer.components import ComponentCatalog, ComponentSpec
from hermes_installer.state import OwnedRoot

class ComponentTests(unittest.TestCase):
    def test_imported_content_is_not_source_resolved_or_discoverable_without_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/"source"; source.mkdir(); (source/"SKILL.md").write_text("# fixture")
            catalog=ComponentCatalog([ComponentSpec("design-pack","https://example.invalid/x","a"*40,license="MIT")])
            imported=catalog.import_skill("design-pack",source,OwnedRoot(root/"owned"))
            self.assertFalse(imported.source_resolved)
            self.assertFalse(imported.discoverable)
            self.assertFalse(imported.redistribution_allowed)
            manifest=json.loads((imported.destination/"import-manifest.json").read_text())
            self.assertEqual("MIT",manifest["license"])
            self.assertFalse(manifest["redistribution_allowed"])
            self.assertEqual("pending_verified_rights",manifest["redistribution_review_status"])
            with self.assertRaises(RuntimeError): catalog.mark_discovered(imported,lambda _:True)

    def test_existing_generation_with_unverified_redistribution_claim_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/"source"; source.mkdir(); (source/"SKILL.md").write_text("# fixture")
            catalog=ComponentCatalog([ComponentSpec("design-pack","https://example.invalid/x","b"*40,license="Apache-2.0")])
            imported=catalog.import_skill("design-pack",source,OwnedRoot(root/"owned"))
            manifest=imported.destination/"import-manifest.json"
            metadata=json.loads(manifest.read_text()); metadata["redistribution_allowed"]=True
            manifest.chmod(0o644); manifest.write_text(json.dumps(metadata))
            with self.assertRaisesRegex(PermissionError,"conflicts with existing owned data"):
                catalog.import_skill("design-pack",source,OwnedRoot(root/"owned"))
    def test_alias_and_application_gates_fail_closed(self):
        with self.assertRaises(ValueError):
            ComponentCatalog([ComponentSpec("a","u","r",aliases=("same",)),ComponentSpec("b","u","r",aliases=("SAME",))])
        catalog=ComponentCatalog([ComponentSpec("app","u","r",kind="application")])
        ready,_=catalog.application_gate("app",{"network"},{"network"},dependencies_verified=True,arm64_verified=True,isolation_verified=True)
        self.assertFalse(ready)
if __name__=="__main__": unittest.main()
