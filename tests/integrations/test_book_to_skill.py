"""Pinned upstream text extraction and Hermes source-skill discovery."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.book_to_skill import book_to_skill_status
from hermes_installer.components.source_selection import select_component_source
from hermes_installer.components.skills import SkillStore


SOURCE = Path(os.environ.get("HERMES_BOOK_TO_SKILL_SOURCE", "/missing/book-to-skill"))
PIN = "e180fc46365e8c1aab0120778cc8a40b9515324b"


@unittest.skipUnless(SOURCE.is_dir(), "set HERMES_BOOK_TO_SKILL_SOURCE to the pinned upstream checkout")
class BookToSkillTests(unittest.TestCase):
    def test_pinned_extractor_handles_rights_authorized_text_fixture_and_source_skill_discovery(self):
        selected = select_component_source(
            "book-to-skill",
            identity="virgiliojr94/book-to-skill",
            url="https://github.com/virgiliojr94/book-to-skill",
            revision=PIN,
            explicit_selection=False,
        )
        self.assertEqual("selected-by-user-star-policy", selected.source_selection)
        with self.assertRaisesRegex(ValueError, "explicit source selection"):
            select_component_source(
                "book-to-skill",
                identity="apple-ouyang/book-to-skill",
                url="https://github.com/apple-ouyang/book-to-skill",
                revision="a24960ac89a3baa96a87cdf5ebaecf16c5d2eab1",
                explicit_selection=False,
            )
        self.assertEqual(PIN, subprocess.check_output(
            ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
        ).strip())
        remote = subprocess.check_output(
            ["git", "-C", str(SOURCE), "remote", "get-url", "origin"], text=True
        ).strip().removesuffix(".git").removesuffix("/")
        self.assertEqual("https://github.com/virgiliojr94/book-to-skill", remote)
        self.assertTrue((SOURCE / "LICENSE.md").is_file())
        self.assertTrue((SOURCE / "SKILL.md").is_file())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pinned_source = root / "source"
            shutil.copytree(SOURCE, pinned_source, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            document = root / "owned-fixture.txt"
            document.write_text(
                "Chapter 1: A Testable Method\n\nA useful rule is to verify one effect at a time.\n",
                encoding="utf-8",
            )
            work = root / "private-work"
            work.mkdir(mode=0o700)
            # This executes the exact pinned converter only over this synthetic,
            # rights-authorized fixture. Runtime adapter execution stays pending
            # until a managed isolated extraction environment is registered.
            code = (
                "import sys; sys.dont_write_bytecode = True; "
                "sys.path.insert(0, sys.argv.pop(1)); "
                "from book_to_skill.utils import main; main()"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(pinned_source), str(document), "--no-install-missing"],
                cwd=work,
                env={"PATH": os.defpath, "BOOK_SKILL_WORKDIR": str(work), "HOME": str(work)},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
                close_fds=True,
            )
            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))
            extracted = work / "full_text.txt"
            metadata_path = work / "metadata.json"
            self.assertIn("verify one effect at a time", extracted.read_text(encoding="utf-8"))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(1, metadata["total_sources"])
            status = book_to_skill_status()
            self.assertEqual("selected-by-user-star-policy", status.source_selection)
            self.assertIn("discoverable", status.source_skill_status)
            self.assertIn("pending", status.generation_status)
            self.assertIn("pending", status.profile_activation_status)
            discovered = SkillStore([pinned_source]).discover()
            self.assertIn(pinned_source.resolve(), discovered)


if __name__ == "__main__":
    unittest.main()
