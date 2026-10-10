"""Real Linux filesystem/socket effects for the held listener binder.

These tests exercise the production bind helper in an isolated root Linux
container. They do not mint setup/actor receipts or claim selected-host proof.
"""
from __future__ import annotations

import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path

from hermes_installer.authority.native_worker_endpoint_custody import (
    PreparedAuthorityEndpointUnavailable,
    _bind_owned_listener,
)


@unittest.skipUnless(os.sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires an isolated Linux root fixture")
class NativeWorkerEndpointBinderLinuxTests(unittest.TestCase):
    service_gid = 43109

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="hermes-endpoint-")
        self.directory = Path(self.temporary.name)
        os.chmod(self.directory, 0o711)
        self.directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def tearDown(self) -> None:
        os.close(self.directory_fd)
        self.temporary.cleanup()

    def test_binds_real_root_owned_listening_socket_and_accepts_connection(self) -> None:
        leaf = "43109.sock"
        listener, bound = _bind_owned_listener(self.directory_fd, leaf, self.service_gid)
        try:
            self.assertTrue(stat.S_ISSOCK(bound.st_mode))
            self.assertEqual((bound.st_uid, bound.st_gid, stat.S_IMODE(bound.st_mode)),
                             (0, self.service_gid, 0o660))
            self.assertEqual(listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1)
            self.assertEqual((listener.family, listener.type & socket.SOCK_STREAM),
                             (socket.AF_UNIX, socket.SOCK_STREAM))
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(str(self.directory / leaf))
                peer, _ = listener.accept()
                peer.close()
            finally:
                client.close()
        finally:
            listener.close()
            current = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (bound.st_dev, bound.st_ino):
                os.unlink(leaf, dir_fd=self.directory_fd)

    def test_conflicting_existing_socket_is_never_adopted_or_unlinked(self) -> None:
        leaf = "43110.sock"
        foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        foreign.bind(str(self.directory / leaf))
        before = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
        try:
            with self.assertRaises(PreparedAuthorityEndpointUnavailable):
                _bind_owned_listener(self.directory_fd, leaf, self.service_gid)
            after = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertTrue(stat.S_ISSOCK(after.st_mode))
        finally:
            foreign.close()
            os.unlink(leaf, dir_fd=self.directory_fd)

    def test_conflicting_regular_file_is_preserved(self) -> None:
        leaf = "43111.sock"
        path = self.directory / leaf
        path.write_bytes(b"foreign")
        before = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
        with self.assertRaises(PreparedAuthorityEndpointUnavailable):
            _bind_owned_listener(self.directory_fd, leaf, self.service_gid)
        after = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(path.read_bytes(), b"foreign")

    def test_conflicting_symlink_is_preserved_without_following_target(self) -> None:
        leaf = "43113.sock"
        target = self.directory / "outside-target"
        target.write_bytes(b"foreign-target")
        (self.directory / leaf).symlink_to(target)
        before = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
        with self.assertRaises(PreparedAuthorityEndpointUnavailable):
            _bind_owned_listener(self.directory_fd, leaf, self.service_gid)
        after = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
        self.assertTrue(stat.S_ISLNK(after.st_mode))
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(target.read_bytes(), b"foreign-target")

    def test_invalid_group_fails_before_any_leaf_is_created(self) -> None:
        with self.assertRaises(PreparedAuthorityEndpointUnavailable):
            _bind_owned_listener(self.directory_fd, "43112.sock", 0)
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
