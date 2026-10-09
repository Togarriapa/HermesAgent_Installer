"""Effect and recovery tests for fixed root installed-stage publication."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending
from hermes_installer.authority.installed_stage_publisher import (
    _canonical, _publish_retained_build, _recover_staging_journals, _sha,
)


@dataclass(frozen=True)
class FileRow:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    roles: tuple[str, ...]
    device: int
    inode: int


@dataclass(frozen=True)
class Predecessor:
    parent_device: int
    parent_inode: int
    state: str = "absent"
    sha256: str | None = None
    device: int | None = None
    inode: int | None = None
    candidate_git_sha: str | None = None


class BuildReceipt:
    def __init__(self, path: Path, files: tuple[FileRow, ...], output_root: Path):
        self.candidate_git_sha = "a" * 40
        self.receipt_handle = "receipt_handle_for_test_0123456789abcdef"
        self.files = files
        self.output_device = os.stat(output_root).st_dev
        self.closure_manifest_relative_path = "release-manifest.json"
        self.closure_manifest_sha256 = ""  # The writer independently recomputes the canonical closure manifest.
        rows = [{"relative_path": f.relative_path, "sha256": f.sha256,
                 "size_bytes": f.size_bytes, "mode": f.mode, "roles": list(f.roles)} for f in files]
        self.role_closure_manifest_sha256 = _sha(_canonical({
            "schema": 1, "candidate_git_sha": self.candidate_git_sha, "files": rows}))
        self.closure_manifest_sha256 = self.role_closure_manifest_sha256
        self.baseline_tree_sha256 = _sha(_canonical({
            f.relative_path.removeprefix("plans/2026-10-09-v1/"): f.sha256
            for f in files if f.relative_path.startswith("plans/2026-10-09-v1/")
        }))
        self.source_tree_sha256 = "b" * 64
        self._path = path

    def verify_current(self):
        return None

    def open_file(self, relative_path: str) -> int:
        if relative_path != self.files[0].relative_path:
            raise ValueError("unexpected path")
        return os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)


class InstalledStagePublicationTests(unittest.TestCase):
    def _fixture(self, temp: str):
        root = Path(temp)
        output = root / "output"
        output.mkdir(mode=0o700)
        source = output / "baseline-file"
        source.write_bytes(b"verified source bytes")
        os.chmod(source, 0o444)
        data = source.read_bytes()
        source_info = os.stat(source)
        row = FileRow("plans/2026-10-09-v1/README.md", hashlib.sha256(data).hexdigest(),
                      len(data), 0o444, ("baseline",), source_info.st_dev, source_info.st_ino)
        receipt = BuildReceipt(source, (row,), output)
        deploy = root / "deployments"
        deploy.mkdir(mode=0o700)
        releases = root / "releases"
        releases.mkdir(mode=0o700)
        predecessor = Predecessor(os.stat(deploy).st_dev, os.stat(deploy).st_ino)
        return root, receipt, deploy / "current.json", releases / receipt.candidate_git_sha, predecessor

    def test_stages_verified_closure_and_publishes_pointer_last(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            _publish_retained_build(receipt=receipt, release_root=release, receipt_path=record_path,
                                    expected_uid=os.getuid(), predecessor=predecessor)
            record = json.loads(record_path.read_bytes())
            self.assertEqual(record["release_root"], str(release))
            self.assertEqual(record["closure_manifest_relative_path"], "release-manifest.json")
            self.assertEqual((release / "plans/2026-10-09-v1/README.md").read_bytes(),
                             b"verified source bytes")
            self.assertEqual((release / "release-manifest.json").read_bytes(), _canonical({
                "schema": 1, "candidate_git_sha": receipt.candidate_git_sha,
                "files": [{"relative_path": receipt.files[0].relative_path,
                           "sha256": receipt.files[0].sha256,
                           "size_bytes": receipt.files[0].size_bytes,
                           "mode": receipt.files[0].mode,
                           "roles": ["baseline"]}]}))
            self.assertEqual(os.stat(release).st_mode & 0o777, 0o555)
            self.assertEqual(os.stat(record_path).st_mode & 0o777, 0o600)

    def test_stale_predecessor_denies_before_release_or_pointer_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            record_path.write_bytes(_canonical({"candidate_git_sha": "c" * 40}))
            os.chmod(record_path, 0o600)
            before = record_path.read_bytes()
            with self.assertRaises(BootstrapEnrollmentPending):
                _publish_retained_build(receipt=receipt, release_root=release, receipt_path=record_path,
                                        expected_uid=os.getuid(), predecessor=predecessor)
            self.assertEqual(record_path.read_bytes(), before)
            self.assertFalse(release.exists())

    def test_existing_candidate_with_extra_content_is_preserved_and_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            release.mkdir(mode=0o555)
            os.chmod(release, 0o755)
            marker = release / "foreign"
            marker.write_bytes(b"keep")
            os.chmod(marker, 0o444)
            os.chmod(release, 0o555)
            with self.assertRaises(BootstrapEnrollmentError):
                _publish_retained_build(receipt=receipt, release_root=release, receipt_path=record_path,
                                        expected_uid=os.getuid(), predecessor=predecessor)
            self.assertEqual(marker.read_bytes(), b"keep")
            self.assertFalse(record_path.exists())

    def test_failed_pointer_replace_keeps_prior_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            prior = {"schema": 1, "receipt_id": "prior", "candidate_git_sha": "c" * 40,
                     "release_root": "/tmp/other", "release_device": 1, "release_inode": 2,
                     "closure_manifest_relative_path": "release-manifest.json",
                     "closure_manifest_sha256": "d" * 64, "baseline_tree_sha256": "e" * 64,
                     "published_monotonic": 1.0}
            raw = _canonical(prior)
            record_path.write_bytes(raw)
            os.chmod(record_path, 0o600)
            info = os.stat(record_path)
            predecessor = Predecessor(os.stat(record_path.parent).st_dev,
                                      os.stat(record_path.parent).st_ino,
                                      "present", _sha(raw), info.st_dev, info.st_ino, "c" * 40)
            with patch("hermes_installer.authority.installed_stage_publisher.os.replace",
                       side_effect=OSError("injected pointer failure")):
                with self.assertRaises(OSError):
                    _publish_retained_build(receipt=receipt, release_root=release,
                                            receipt_path=record_path, expected_uid=os.getuid(),
                                            predecessor=predecessor)
            self.assertEqual(record_path.read_bytes(), raw)
            self.assertEqual(json.loads(record_path.read_bytes())["receipt_id"], "prior")

    def test_interrupted_candidate_stage_is_recovered_for_same_build_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            with patch("hermes_installer.authority.installed_stage_publisher._rename_noreplace",
                       side_effect=OSError("injected release rename failure")):
                with self.assertRaises(OSError):
                    _publish_retained_build(receipt=receipt, release_root=release,
                                            receipt_path=record_path, expected_uid=os.getuid(),
                                            predecessor=predecessor)
            stage_journals = tuple((record_path.parent.parent / "releases").glob(".stage-*.journal.json"))
            self.assertEqual(len(stage_journals), 1)
            self.assertFalse(release.exists())
            _publish_retained_build(receipt=receipt, release_root=release,
                                    receipt_path=record_path, expected_uid=os.getuid(),
                                    predecessor=predecessor)
            self.assertTrue(release.is_dir())
            self.assertTrue(record_path.is_file())
            self.assertEqual(tuple((record_path.parent.parent / "releases").glob(".stage-*.journal.json")), ())

    def test_recovery_refuses_matching_symlink_journal_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root, receipt, record_path, release, _ = self._fixture(temp)
            releases = release.parent
            source = root / "important"
            source.write_bytes(b"preserve")
            prefix = f".stage-{receipt.candidate_git_sha}-{_sha(receipt.receipt_handle.encode())[:16]}-"
            journal = releases / (prefix + "foreign.journal.json")
            journal.symlink_to(source)
            with self.assertRaises(BootstrapEnrollmentPending):
                _recover_staging_journals(releases, receipt, _canonical({}), os.getuid())
            self.assertTrue(journal.is_symlink())
            self.assertEqual(source.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
