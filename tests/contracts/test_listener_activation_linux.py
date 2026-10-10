"""Real pathname Unix credentials and SCM_RIGHTS tests for HI-T187 transport."""
from __future__ import annotations

import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.listener_activation import (
    ListenerActivationUnavailable,
    _activation_message,
    _create_control_listener,
    _recv_packet,
    _send_packet,
    _verify_transferred_listener,
)


@unittest.skipUnless(os.sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires isolated Linux root fixture")
class ListenerActivationTransportLinuxTests(unittest.TestCase):
    def test_activation_listener_uses_canonical_held_directory_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hermes-activation-root-") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            activation_root = root / "listener-activation"
            activation_id = "ab" * 16
            with patch("hermes_installer.authority.listener_activation._CONTROL_ROOT", activation_root):
                prefix_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                prefix_info = os.fstat(prefix_fd)
                root_fd, activation_fd, listener, _identity = _create_control_listener(
                    activation_id, prefix_fd, (prefix_info.st_dev, prefix_info.st_ino))
                expected = str(activation_root / activation_id / "control.sock")
                self.assertEqual(listener.getsockname(), expected)
                socket_info = os.stat("control.sock", dir_fd=activation_fd, follow_symlinks=False)
                named_info = Path(expected).lstat()
                self.assertTrue(stat.S_ISSOCK(socket_info.st_mode))
                self.assertEqual((socket_info.st_dev, socket_info.st_ino),
                                 (named_info.st_dev, named_info.st_ino))
                self.assertEqual(stat.S_IMODE(named_info.st_mode), 0o600)
                listener.close()
                os.unlink("control.sock", dir_fd=activation_fd)
                os.close(activation_fd)
                os.rmdir(activation_id, dir_fd=root_fd)
                os.close(root_fd)
                os.rmdir(activation_root)
                os.close(prefix_fd)

    def test_pathname_seqpacket_transfers_exact_listening_fd_across_processes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hermes-activation-") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            control_path = root / "control.sock"
            authority_path = root / "0.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(authority_path))
            os.chmod(authority_path, 0o660)
            identity = authority_path.lstat()
            listener.listen(2)
            channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            channel.bind(str(control_path))
            os.chmod(control_path, 0o600)
            channel.listen(1)
            nonce = bytes.fromhex("ab" * 32)
            message = _activation_message(
                operation="transfer-listener", activation_id="11" * 16,
                nonce=nonce, record_sha256="22" * 32,
                publication_handle="publication-receipt",
                publication_sha256="33" * 32,
                generation_sha256="44" * 32,
                endpoint_sha256="55" * 32,
                socket_device=identity.st_dev, socket_inode=identity.st_ino)
            child = os.fork()
            if child == 0:
                try:
                    channel.close()
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    connection.connect(str(control_path))
                    _send_packet(connection, message, fd=listener.fileno())
                    connection.close()
                    os._exit(0)
                except BaseException:
                    os._exit(2)
            channel_conn, _ = channel.accept()
            channel_conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            try:
                packet, descriptors = _recv_packet(
                    channel_conn, expected_peer=(child, 0, 0), expected_fd_count=1)
                self.assertEqual(packet, message)
                self.assertEqual(len(descriptors), 1)
                adopted = _verify_transferred_listener(
                    descriptors[0], socket_device=identity.st_dev,
                    socket_inode=identity.st_ino, owner_uid=0, owner_gid=0,
                    socket_root=root)
                try:
                    self.assertEqual(adopted.getsockname(), str(authority_path))
                    self.assertEqual(adopted.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1)
                    self.assertFalse(os.get_inheritable(adopted.fileno()))
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.connect(str(authority_path))
                    accepted, _ = adopted.accept()
                    accepted.close()
                    client.close()
                finally:
                    adopted.close()
            finally:
                channel_conn.close()
                channel.close()
                listener.close()
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass

    def test_wrong_pathname_peer_pid_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hermes-activation-peer-") as temporary:
            path = str(Path(temporary) / "control.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            server.bind(path)
            os.chmod(path, 0o600)
            server.listen(1)
            child = os.fork()
            if child == 0:
                try:
                    server.close()
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    client.connect(path)
                    _send_packet(client, {"schema": 1, "operation": "bad"})
                    client.close()
                    os._exit(0)
                except BaseException:
                    os._exit(2)
            accepted, _ = server.accept()
            try:
                with self.assertRaises(ListenerActivationUnavailable):
                    _recv_packet(accepted, expected_peer=(-1, 0, 0), expected_fd_count=0)
            finally:
                accepted.close()
                server.close()
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass


def test_activation_generation_join_uses_actual_committed_row_fields() -> None:
    from types import SimpleNamespace
    from hermes_installer.authority.listener_activation import _activation_generation_rows, _digest
    from hermes_installer.authority.native_worker_service_generation import RootPreparedNativeServiceGeneration

    runtime = {"id": "runtime-1", "generation_id": "container-1", "profile_id": "worker-1"}
    active = {
        "worker_runtime_record_id": "runtime-1",
        "worker_runtime_record_sha256": _digest(runtime),
        "process_profile_id": "worker-1",
    }
    profile = {"profile_id": "worker-1"}
    service = {"profile_id": "worker-1", "service_uid": 1000, "service_gid": 1000}
    generation = object.__new__(RootPreparedNativeServiceGeneration)
    for name, value in {
        "generation_id": "container-1",
        "native_worker_runtime_records": (runtime,),
        "active_network_generation_records": (active,),
        "process_profile_records": (profile,),
        "service_records": (service,),
    }.items():
        object.__setattr__(generation, name, value)
    publication = SimpleNamespace(generation_id="container-1", service_generation_digest="a" * 64)
    endpoint = SimpleNamespace(profile_id="worker-1", service_uid=1000, service_gid=1000)

    assert _activation_generation_rows(generation, publication, endpoint) == (
        runtime, active, profile, service)

    # The container ID and service-generation digest are distinct joined values.
    publication.generation_id = "a" * 64
    with unittest.TestCase().assertRaises(ValueError):
        _activation_generation_rows(generation, publication, endpoint)
    publication.generation_id = "container-1"

    # Producer rows use process_profile_id, not the endpoint's profile_id alias.
    wrong_active = {**active, "profile_id": "worker-1"}
    wrong_active.pop("process_profile_id")
    object.__setattr__(generation, "active_network_generation_records", (wrong_active,))
    with unittest.TestCase().assertRaises(ValueError):
        _activation_generation_rows(generation, publication, endpoint)

if __name__ == "__main__":
    unittest.main()
