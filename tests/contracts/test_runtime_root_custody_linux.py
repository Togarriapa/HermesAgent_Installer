"""Filesystem effects for cold authority runtime-root custody on Linux."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.runtime_root_custody import (
    RootPreparedAuthorityRootReceipt,
    RuntimeRootCustodyUnavailable,
    _SEAL,
    _open_fixed_directory,
    _open_journal_owned_directory,
    _read_journal,
    _write_journal,
)


@unittest.skipUnless(os.sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires an isolated Linux root fixture")
class RuntimeRootCustodyLinuxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="hermes-runtime-root-")
        self.base = Path(self.temporary.name)
        os.chmod(self.base, 0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exclusive_create_records_inode_and_adoption_rechecks_exact_inode(self) -> None:
        run_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        created: list[tuple[int, str, int, int]] = []
        try:
            prefix_fd, prefix, made = _open_fixed_directory(run_fd, "hermes-installer", None,
                                                               0o711, created)
            self.assertTrue(made)
            self.assertEqual((prefix.st_uid, prefix.st_gid, stat.S_IMODE(prefix.st_mode)), (0, 0, 0o711))
            journal = {"schema": 1, "journal": {"root_id": "fixture"},
                       "prefix": {"device": prefix.st_dev, "inode": prefix.st_ino}, "authority": None}
            authority_fd, authority, made_authority = _open_fixed_directory(
                prefix_fd, "authority", None, 0o711, created)
            self.assertTrue(made_authority)
            journal["authority"] = {"device": authority.st_dev, "inode": authority.st_ino}
            os.close(authority_fd)
            adopted_fd, adopted, adopted_created = _open_fixed_directory(
                run_fd, "hermes-installer", journal["prefix"], 0o711, [])
            self.assertFalse(adopted_created)
            self.assertEqual((adopted.st_dev, adopted.st_ino), (prefix.st_dev, prefix.st_ino))
            os.close(adopted_fd)
            os.close(prefix_fd)
        finally:
            os.close(run_fd)

    def test_unknown_symlink_wrong_mode_and_replacement_are_preserved(self) -> None:
        run_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            target = self.base / "target"
            target.mkdir(mode=0o711)
            os.symlink(target, self.base / "hermes-installer")
            before = os.lstat(self.base / "hermes-installer")
            with self.assertRaises(RuntimeRootCustodyUnavailable):
                _open_fixed_directory(run_fd, "hermes-installer", None, 0o711, [])
            after = os.lstat(self.base / "hermes-installer")
            self.assertTrue(stat.S_ISLNK(after.st_mode))
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            os.unlink(self.base / "hermes-installer")
            (self.base / "hermes-installer").mkdir(mode=0o700)
            before = os.lstat(self.base / "hermes-installer")
            with self.assertRaises(RuntimeRootCustodyUnavailable):
                _open_fixed_directory(run_fd, "hermes-installer", None, 0o711, [])
            after = os.lstat(self.base / "hermes-installer")
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o700)
        finally:
            os.close(run_fd)

    def test_interrupted_journaled_staging_create_resumes_same_inode(self) -> None:
        run_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        journal_dir = self.base / "journal"
        journal_dir.mkdir(mode=0o700)
        staging = ".hermes-authority-root-fixture"
        try:
            os.mkdir(staging, 0o711, dir_fd=run_fd)
            staged_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run_fd)
            try:
                info = os.fstat(staged_fd)
                document = {"schema": 1, "journal": {"root_id": "fixture"},
                            "prefix": {"state": "pending", "staging": staging,
                                       "device": info.st_dev, "inode": info.st_ino}, "authority": None}
                _write_journal(journal_dir, document)
            finally:
                os.close(staged_fd)
            recovered_fd, recovered, created = _open_journal_owned_directory(
                run_fd, "hermes-installer", document["prefix"], 0o711, [],
                journal_dir, document, "prefix")
            try:
                self.assertFalse(created)
                self.assertEqual((recovered.st_dev, recovered.st_ino), (info.st_dev, info.st_ino))
                self.assertEqual(_read_journal(journal_dir)["prefix"],
                                 {"state": "owned", "device": info.st_dev, "inode": info.st_ino})
            finally:
                os.close(recovered_fd)
        finally:
            os.close(run_fd)

    def test_interrupted_create_never_adopts_a_racing_foreign_final(self) -> None:
        run_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        journal_dir = self.base / "journal"
        journal_dir.mkdir(mode=0o700)
        staging = ".hermes-authority-root-fixture"
        try:
            os.mkdir(staging, 0o711, dir_fd=run_fd)
            staged = os.stat(staging, dir_fd=run_fd, follow_symlinks=False)
            os.mkdir("hermes-installer", 0o711, dir_fd=run_fd)
            foreign = os.stat("hermes-installer", dir_fd=run_fd, follow_symlinks=False)
            document = {"schema": 1, "journal": {"root_id": "fixture"},
                        "prefix": {"state": "pending", "staging": staging,
                                   "device": staged.st_dev, "inode": staged.st_ino}, "authority": None}
            _write_journal(journal_dir, document)
            with self.assertRaises(RuntimeRootCustodyUnavailable):
                _open_journal_owned_directory(run_fd, "hermes-installer", document["prefix"],
                                              0o711, [], journal_dir, document, "prefix")
            after = os.stat("hermes-installer", dir_fd=run_fd, follow_symlinks=False)
            self.assertEqual((after.st_dev, after.st_ino), (foreign.st_dev, foreign.st_ino))
            self.assertEqual(os.stat(staging, dir_fd=run_fd).st_ino, staged.st_ino)
        finally:
            os.close(run_fd)

    def test_receipt_cleanup_removes_only_its_empty_inode_and_updates_journal(self) -> None:
        run_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        created: list[tuple[int, str, int, int]] = []
        prefix_fd = root_fd = -1
        try:
            run = os.fstat(run_fd)
            prefix_fd, prefix, _ = _open_fixed_directory(run_fd, "hermes-installer", None, 0o711, created)
            root_fd, root, _ = _open_fixed_directory(prefix_fd, "authority", None, 0o711, created)
            journal_dir = self.base / "journal"
            journal_dir.mkdir(mode=0o700)
            journal = {"schema": 1, "journal": {"root_id": "fixture"},
                       "prefix": {"device": prefix.st_dev, "inode": prefix.st_ino},
                       "authority": {"device": root.st_dev, "inode": root.st_ino}}
            _write_journal(journal_dir, journal)
            binding = SimpleNamespace(_session=SimpleNamespace(_check_live=lambda: None))
            actor = SimpleNamespace(verify_current=lambda _release: None)
            receipt = RootPreparedAuthorityRootReceipt(
                session_id="fixture", transaction_handle="transaction", plan_digest="p" * 64,
                release_commit="c" * 40, actor_pid=os.getpid(), actor_start_time=1,
                device=root.st_dev, inode=root.st_ino, _binding=binding, _release=object(), _actor=actor,
                _journal_path=journal_dir, _run_fd=run_fd, _prefix_fd=prefix_fd, _root_fd=root_fd,
                _run_identity=(run.st_dev, run.st_ino), _prefix_identity=(prefix.st_dev, prefix.st_ino),
                _root_identity=(root.st_dev, root.st_ino), _created=tuple(created), _seal=_SEAL)
            receipt.cleanup_created_empty()
            self.assertFalse((self.base / "hermes-installer").exists())
            current = _read_journal(journal_dir)
            self.assertIsNone(current["prefix"])
            self.assertIsNone(current["authority"])
            receipt.close()
            run_fd = prefix_fd = root_fd = -1
        finally:
            for fd in (root_fd, prefix_fd, run_fd):
                if fd >= 0:
                    os.close(fd)

    def test_cleanup_preserves_nonempty_created_root(self) -> None:
        run_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        created: list[tuple[int, str, int, int]] = []
        prefix_fd = root_fd = -1
        try:
            run = os.fstat(run_fd)
            prefix_fd, prefix, _ = _open_fixed_directory(run_fd, "hermes-installer", None, 0o711, created)
            root_fd, root, _ = _open_fixed_directory(prefix_fd, "authority", None, 0o711, created)
            journal_dir = self.base / "journal"
            journal_dir.mkdir(mode=0o700)
            _write_journal(journal_dir, {"schema": 1, "journal": {"root_id": "fixture"},
                                         "prefix": {"device": prefix.st_dev, "inode": prefix.st_ino},
                                         "authority": {"device": root.st_dev, "inode": root.st_ino}})
            fd = os.open("keep", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=root_fd)
            os.close(fd)
            binding = SimpleNamespace(_session=SimpleNamespace(_check_live=lambda: None))
            actor = SimpleNamespace(verify_current=lambda _release: None)
            receipt = RootPreparedAuthorityRootReceipt(
                session_id="fixture", transaction_handle="transaction", plan_digest="p" * 64,
                release_commit="c" * 40, actor_pid=os.getpid(), actor_start_time=1,
                device=root.st_dev, inode=root.st_ino, _binding=binding, _release=object(), _actor=actor,
                _journal_path=journal_dir, _run_fd=run_fd, _prefix_fd=prefix_fd, _root_fd=root_fd,
                _run_identity=(run.st_dev, run.st_ino), _prefix_identity=(prefix.st_dev, prefix.st_ino),
                _root_identity=(root.st_dev, root.st_ino), _created=tuple(created), _seal=_SEAL)
            receipt.cleanup_created_empty()
            self.assertEqual((os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino),
                             (root.st_dev, root.st_ino))
            self.assertEqual(_read_journal(journal_dir)["authority"],
                             {"device": root.st_dev, "inode": root.st_ino})
            receipt.close()
            run_fd = prefix_fd = root_fd = -1
        finally:
            for fd in (root_fd, prefix_fd, run_fd):
                if fd >= 0:
                    os.close(fd)


if __name__ == "__main__":
    unittest.main()
