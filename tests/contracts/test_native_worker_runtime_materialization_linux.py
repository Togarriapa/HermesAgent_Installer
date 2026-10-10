"""Root Linux filesystem effects for native output member custody."""
from __future__ import annotations

import hashlib
import fcntl
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from hermes_installer.authority.native_worker_runtime_materialization import (
    NativeWorkerRuntimeMaterializationUnavailable,
    RootPreparedNativeWorkerRuntimeMaterializationRegistry,
    _hash_fd,
)


@unittest.skipUnless(os.sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires an isolated Linux root fixture")
class NativeWorkerRuntimeMaterializationLinuxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="hermes-native-runtime-")
        self.parent = Path(self.temporary.name)
        os.chmod(self.parent, 0o700)
        self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.leaf = "r" * 40
        os.mkdir(self.leaf, 0o700, dir_fd=self.parent_fd)
        self.root_fd = os.open(self.leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=self.parent_fd)
        self.registry = object.__new__(RootPreparedNativeWorkerRuntimeMaterializationRegistry)

    def tearDown(self) -> None:
        os.close(self.root_fd)
        os.close(self.parent_fd)
        self.temporary.cleanup()

    def test_materializes_actual_root_file_and_returns_held_inode_witness(self) -> None:
        content = b"verified native output\n"
        expected = SimpleNamespace(
            mode=0o444, size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        held: list[int] = []
        row = self.registry._write_member(
            self.root_fd, "native-action-resolver", "resolver.py", content, expected,
            "native-action-resolver-v1", "output-receipt", held)
        info = os.stat("native-action-resolver/resolver.py", dir_fd=self.root_fd,
                       follow_symlinks=False)
        self.assertEqual((row["device"], row["inode"], row["owner_uid"], row["owner_gid"],
                          row["mode"], row["size_bytes"]),
                         (info.st_dev, info.st_ino, 0, 0, 0o444, len(content)))
        self.assertEqual(_hash_fd(held[0]), expected.sha256)
        self.assertEqual(row["receipt_handle"], "output-receipt")
        self.assertEqual(row["kind"], "regular-file")
        os.close(held[0])

    def test_current_path_replacement_is_detected_even_when_held_fd_survives(self) -> None:
        content = b"held output\n"
        expected = SimpleNamespace(
            mode=0o444, size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        held: list[int] = []
        row = self.registry._write_member(
            self.root_fd, "native-entrypoint-manifest", "manifest.json", content,
            expected, "native-entrypoint-manifest-v1", "output-receipt", held)
        os.unlink("native-entrypoint-manifest/manifest.json", dir_fd=self.root_fd)
        replacement_fd = os.open("native-entrypoint-manifest/manifest.json",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444,
                                 dir_fd=self.root_fd)
        os.write(replacement_fd, content)
        os.close(replacement_fd)
        witness = SimpleNamespace(_root_fd=self.root_fd,
                                  native_output_member_records=(row,))
        try:
            with self.assertRaises(NativeWorkerRuntimeMaterializationUnavailable):
                self.registry._verify_output_member_paths(witness)
        finally:
            os.close(held[0])

    def test_cleanup_preserves_unrecorded_root_owned_data(self) -> None:
        content = b"owned output\n"
        expected = SimpleNamespace(
            mode=0o444, size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        held: list[int] = []
        row = self.registry._write_member(
            self.root_fd, "native-boundary-overlay", "overlay.py", content,
            expected, "native-boundary-overlay-v1", "output-receipt", held)
        os.close(held[0])
        Path(self.parent / self.leaf / "operator-data").write_bytes(b"preserve me")
        root_info = os.fstat(self.root_fd)
        self.registry._remove_leaf_if_owned(
            self.leaf, root_info, (row,), self.parent_fd)
        self.assertEqual((self.parent / self.leaf / "operator-data").read_bytes(), b"preserve me")
        self.assertTrue((self.parent / self.leaf).is_dir())
        self.assertFalse((self.parent / self.leaf / "native-boundary-overlay" / "overlay.py").exists())

    def test_runtime_parent_child_descriptor_closes_on_post_open_failure(self) -> None:
        self.registry.output_receipts = SimpleNamespace(_cas_root=self.parent / "cas")
        opened: list[int] = []
        original_open = os.open

        def recording_open(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd

        with mock.patch.object(os, "open", side_effect=recording_open), \
                mock.patch.object(os, "fchmod", side_effect=OSError("injected")):
            with self.assertRaises(NativeWorkerRuntimeMaterializationUnavailable):
                self.registry._open_or_create_runtime_parent()
        self.assertEqual(len(opened), 2)
        for descriptor in opened:
            with self.assertRaises(OSError):
                fcntl.fcntl(descriptor, fcntl.F_GETFD)


if __name__ == "__main__":
    unittest.main()
