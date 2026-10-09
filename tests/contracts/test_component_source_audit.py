"""End-to-end source import preserves helpers and fails before owned writes."""
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components import ComponentCatalog, ComponentSpec
from hermes_installer.state import OwnedRoot


class ComponentSourceAuditTests(unittest.TestCase):
    def test_import_keeps_helper_and_shared_root_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            skill = source / "skills" / "demo"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "[helper](scripts/check.py)\n[shared reference](../../README.md)\n",
                encoding="utf-8",
            )
            (skill / "scripts").mkdir()
            (skill / "scripts" / "check.py").write_text("print('ok')\n", encoding="utf-8")
            (source / "README.md").write_text("shared data\n", encoding="utf-8")
            owned = OwnedRoot(root / "managed")
            catalog = ComponentCatalog([
                ComponentSpec("demo", "https://github.com/example/demo", "a" * 40)
            ])

            imported = catalog.import_skill("demo", source, owned)

            self.assertEqual(
                "print('ok')\n",
                (imported.destination / "skills/demo/scripts/check.py").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                "shared data\n",
                (imported.destination / "README.md").read_text(encoding="utf-8"),
            )
            self.assertIn("skills/demo/scripts/check.py", imported.files)
            self.assertFalse(imported.discoverable)

    def test_broken_reference_aborts_before_owned_root_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "SKILL.md").write_text("[missing](scripts/not-there.py)\n", encoding="utf-8")
            owned = OwnedRoot(root / "managed")
            catalog = ComponentCatalog([
                ComponentSpec("demo", "https://github.com/example/demo", "a" * 40)
            ])

            with self.assertRaisesRegex(ValueError, "referenced file or directory is missing"):
                catalog.import_skill("demo", source, owned)

            self.assertFalse(owned.root.exists())


if __name__ == "__main__":
    unittest.main()
