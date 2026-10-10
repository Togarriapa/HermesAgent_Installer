"""Real Linux filesystem/socket effects for the held listener binder.

These tests exercise the production bind helper in an isolated root Linux
container. They do not mint setup/actor receipts or claim selected-host proof.
"""
from __future__ import annotations

import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

import hermes_installer.authority.native_worker_endpoint_custody as custody
from hermes_installer.authority.native_worker_endpoint_custody import (
    PreparedAuthorityEndpointUnavailable,
    RootPreparedAuthorityEndpointCustodian,
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

    def test_expiry_revokes_only_the_exact_owned_leaf_and_closes_descriptors(self) -> None:
        leaf = "43114.sock"
        listener, bound = _bind_owned_listener(self.directory_fd, leaf, self.service_gid)
        stop = threading.Event()
        identity_handle = "identity-receipt"
        receipt = SimpleNamespace(
            receipt_handle="endpoint-receipt",
            service_identity_receipt_handle=identity_handle,
            service_uid=43114, service_gid=self.service_gid,
            socket_device=bound.st_dev, socket_inode=bound.st_ino,
            expires_monotonic=time.monotonic() - 1,
        )
        directory_fd = os.dup(self.directory_fd)
        custodian = RootPreparedAuthorityEndpointCustodian.__new__(RootPreparedAuthorityEndpointCustodian)
        custodian._lock = threading.RLock()
        custodian._closed = False
        custodian._listeners = {identity_handle: (
            listener, directory_fd, (bound.st_dev, bound.st_ino), stop, threading.current_thread())}
        custodian._receipts = {receipt.receipt_handle: receipt}
        custodian._expire_listener(receipt, stop)
        self.assertTrue(stop.is_set())
        self.assertNotIn(identity_handle, custodian._listeners)
        self.assertNotIn(receipt.receipt_handle, custodian._receipts)
        with self.assertRaises(FileNotFoundError):
            os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
        with self.assertRaises(OSError):
            os.fstat(directory_fd)

    def test_expiry_does_not_unlink_a_replacement_socket(self) -> None:
        leaf = "43115.sock"
        listener, bound = _bind_owned_listener(self.directory_fd, leaf, self.service_gid)
        os.unlink(leaf, dir_fd=self.directory_fd)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(self.directory / leaf))
        replacement_info = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
        stop = threading.Event()
        receipt = SimpleNamespace(
            receipt_handle="endpoint-receipt-replaced",
            service_identity_receipt_handle="identity-receipt-replaced",
            service_uid=43115, service_gid=self.service_gid,
            socket_device=bound.st_dev, socket_inode=bound.st_ino,
            expires_monotonic=time.monotonic() - 1,
        )
        directory_fd = os.dup(self.directory_fd)
        custodian = RootPreparedAuthorityEndpointCustodian.__new__(RootPreparedAuthorityEndpointCustodian)
        custodian._lock = threading.RLock()
        custodian._closed = False
        custodian._listeners = {receipt.service_identity_receipt_handle: (
            listener, directory_fd, (bound.st_dev, bound.st_ino), stop, threading.current_thread())}
        custodian._receipts = {receipt.receipt_handle: receipt}
        try:
            custodian._expire_listener(receipt, stop)
            after = os.stat(leaf, dir_fd=self.directory_fd, follow_symlinks=False)
            self.assertTrue(stat.S_ISSOCK(after.st_mode))
            self.assertEqual((after.st_dev, after.st_ino),
                             (replacement_info.st_dev, replacement_info.st_ino))
        finally:
            listener.close()
            replacement.close()
            os.unlink(leaf, dir_fd=self.directory_fd)

    def test_open_directory_closes_fd_when_post_open_observation_fails(self) -> None:
        opened: list[int] = []
        original_dup = os.dup

        def recording_dup(*args, **kwargs):
            fd = original_dup(*args, **kwargs)
            opened.append(fd)
            return fd

        custodian = RootPreparedAuthorityEndpointCustodian.__new__(RootPreparedAuthorityEndpointCustodian)
        root_info = os.fstat(self.directory_fd)
        custodian.prepared_authority_root_receipt = SimpleNamespace(
            root_fd=self.directory_fd, device=root_info.st_dev, inode=root_info.st_ino,
            verify_current=lambda: None,
        )
        with mock.patch.object(custody.os, "dup", side_effect=recording_dup), \
                mock.patch.object(custody.os, "fstat", side_effect=OSError("injected")):
            with self.assertRaises(PreparedAuthorityEndpointUnavailable):
                custodian._open_directory()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])


if __name__ == "__main__":
    unittest.main()
