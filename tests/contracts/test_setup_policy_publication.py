"""Filesystem effect and conflict tests for root policy publication helpers."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending
from hermes_installer.authority.setup_policy_publication import (
    _FileSpec, _atomic_replace, _ensure_generation, _read_fixed,
)


class PolicyPublicationFilesystemTests(unittest.TestCase):
    def test_generation_install_is_immutable_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "generations"
            parent.mkdir(mode=0o700)
            generation = parent / ("a" * 64)
            files = (
                _FileSpec("plans/bootstrap-policy-v1.json", b"{}"),
                _FileSpec("catalog/artifacts.json", b"{}"),
                _FileSpec("publication.json", b"{}"),
            )
            _ensure_generation(parent, generation, "a" * 64, b"{}", files, os.getuid())
            before = os.stat(generation, follow_symlinks=False)
            _ensure_generation(parent, generation, "a" * 64, b"{}", files, os.getuid())
            after = os.stat(generation, follow_symlinks=False)
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(before.st_mode & 0o777, 0o555)
            self.assertEqual((generation / "plans/bootstrap-policy-v1.json").read_bytes(), b"{}")

    def test_generation_collision_with_foreign_or_extra_content_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "generations"
            parent.mkdir(mode=0o700)
            generation = parent / ("b" * 64)
            generation.mkdir(mode=0o700)
            marker = generation / "foreign"
            marker.write_bytes(b"preserve")
            os.chmod(marker, 0o444)
            os.chmod(generation, 0o555)
            with self.assertRaises(BootstrapEnrollmentError):
                _ensure_generation(parent, generation, "b" * 64, b"{}", (), os.getuid())
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_selection_replace_is_cas_and_rejects_inode_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selection.json"
            path.write_bytes(b"old")
            os.chmod(path, 0o600)
            info = os.stat(path)
            _atomic_replace(path, b"new", os.getuid(), 0o600, (info.st_dev, info.st_ino))
            self.assertEqual(_read_fixed(path, os.getuid(), 0o600, 100)[0], b"new")
            with self.assertRaises(BootstrapEnrollmentPending):
                _atomic_replace(path, b"stale", os.getuid(), 0o600, (info.st_dev, info.st_ino))
            self.assertEqual(path.read_bytes(), b"new")

    def test_selection_replace_rejects_symlink_and_does_not_touch_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_bytes(b"keep")
            os.chmod(target, 0o600)
            path = root / "selection.json"
            path.symlink_to(target)
            with self.assertRaises(BootstrapEnrollmentPending):
                _atomic_replace(path, b"replacement", os.getuid(), 0o600, (1, 1))
            self.assertEqual(target.read_bytes(), b"keep")
            self.assertTrue(path.is_symlink())

    def test_failed_atomic_replace_preserves_previous_selection_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selection.json"
            path.write_bytes(b"before")
            os.chmod(path, 0o600)
            info = os.stat(path)
            with patch("hermes_installer.authority.setup_policy_publication.os.replace",
                       side_effect=OSError("injected rename failure")):
                with self.assertRaises(OSError):
                    _atomic_replace(path, b"after", os.getuid(), 0o600,
                                    (info.st_dev, info.st_ino))
            self.assertEqual(path.read_bytes(), b"before")
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["selection.json"])


if __name__ == "__main__":
    unittest.main()
