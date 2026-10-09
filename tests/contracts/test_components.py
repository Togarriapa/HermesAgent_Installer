"""Pending adapters fail closed instead of claiming runtime completion."""
import tempfile
import unittest
from pathlib import Path
from hermes_installer.components import ComponentCatalog, ComponentSpec
from hermes_installer.state import OwnedRoot

class ComponentTests(unittest.TestCase):
    def test_imported_content_is_not_source_resolved_or_discoverable_without_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/"source"; source.mkdir(); (source/"SKILL.md").write_text("# fixture")
            catalog=ComponentCatalog([ComponentSpec("design-pack","https://example.invalid/x","a"*40)])
            imported=catalog.import_skill("design-pack",source,OwnedRoot(root/"owned"))
            self.assertFalse(imported.source_resolved)
            self.assertFalse(imported.discoverable)
            with self.assertRaises(RuntimeError): catalog.mark_discovered(imported,lambda _:True)
    def test_alias_and_application_gates_fail_closed(self):
        with self.assertRaises(ValueError):
            ComponentCatalog([ComponentSpec("a","u","r",aliases=("same",)),ComponentSpec("b","u","r",aliases=("SAME",))])
        catalog=ComponentCatalog([ComponentSpec("app","u","r",kind="application")])
        ready,_=catalog.application_gate("app",{"network"},{"network"},dependencies_verified=True,arm64_verified=True,isolation_verified=True)
        self.assertFalse(ready)
if __name__=="__main__": unittest.main()
