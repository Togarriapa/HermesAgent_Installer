from __future__ import annotations

import hashlib
import json
import os
import platform
import pwd
import select
import socket
import subprocess
import sys
import threading
import time
import uuid
import unittest
from dataclasses import replace
from pathlib import Path

from hermes_installer.authority.private_loopback_network import (
    POLICY_ID, POLICY_SHA256, close_root_network_lease,
    create_root_namespace, namespace_path_for, validate_private_loopback_networks,
    verify_root_network_lease,
)
from hermes_installer.authority.host_tool_observation import (
    HostToolObservationDenied, HostToolObservationRegistry,
)


def _service(enrollment: str, profile: str, generation: str, uid: int) -> dict[str, object]:
    return {"enrollment_id": enrollment, "profile_id": profile,
            "generation": generation, "service_uid": uid}


def _setuid(uid: int) -> None:
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)


def _listener_child(uid: int, address: str, port: int, status_fd: int) -> int:
    try:
        _setuid(uid)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(1.5)
        server.bind((address, port))
        server.listen(4)
        os.write(status_fd, b"R")
        try:
            peer, _ = server.accept()
        except TimeoutError:
            server.close()
            return 0
        with peer:
            request = peer.recv(32)
            peer.sendall(b"ok" if request == b"ping" else b"no")
        server.close()
        return 0 if request == b"ping" else 2
    except BaseException:
        try:
            os.write(status_fd, b"E")
        except OSError:
            pass
        return 3


def _start_listener(uid: int, address: str, port: int) -> tuple[int, int]:
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        code = _listener_child(uid, address, port, write_fd)
        os._exit(code)
    os.close(write_fd)
    ready, _, _ = select.select([read_fd], [], [], 2.0)
    signal = os.read(read_fd, 1) if ready else b""
    os.close(read_fd)
    if signal != b"R":
        os.waitpid(pid, 0)
        raise AssertionError("selected listener did not become ready inside its private network")
    return pid, 0


def _client_child(uid: int, address: str, port: int, expected: bool) -> int:
    try:
        _setuid(uid)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(.35)
        try:
            client.connect((address, port))
            if not expected:
                client.close()
                return 1
            client.sendall(b"ping")
            result = client.recv(32)
            client.close()
            return 0 if result == b"ok" else 2
        except (OSError, TimeoutError):
            client.close()
            return 0 if not expected else 3
    except BaseException:
        return 4


def _client(uid: int, address: str, port: int, expected: bool) -> int:
    pid = os.fork()
    if pid == 0:
        os._exit(_client_child(uid, address, port, expected))
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def _wait(pid: int) -> int:
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def _systemd_bind_probe(namespace: Path, uid: int, port: int, *, allowed: bool,
                        allowed_port: int | None) -> subprocess.CompletedProcess[str]:
    """Run an actual transient unit so systemd attaches its cgroup bind BPF."""
    unit = "hermes-loopback-bind-" + uuid.uuid4().hex + ".service"
    probe = (
        "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); "
        "\ntry:\n s.bind(('127.0.0.1',int(sys.argv[1]))); print('BOUND'); sys.exit(0 if sys.argv[2]=='allow' else 31)"
        "\nexcept OSError as e:\n print('DENIED:'+str(e)); sys.exit(0 if sys.argv[2]=='deny' else 32)"
    )
    command = [
        "/usr/bin/systemd-run", "--system", "--quiet", "--wait", "--pipe", "--collect",
        "--unit=" + unit, "--property=Type=exec", "--property=User=" + str(uid),
        "--property=NetworkNamespacePath=" + str(namespace),
        "--property=SocketBindDeny=any",
        "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET",
    ]
    if allowed_port is not None:
        command.append(f"--property=SocketBindAllow=ipv4:tcp:{allowed_port}")
    command.extend(("/usr/bin/python3", "-c", probe, str(port), "allow" if allowed else "deny"))
    return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, timeout=15, check=False)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and Path("/usr/sbin/nft").exists(),
                     "requires root Linux, nftables and private-netns kernel support")
class LinuxPrivateLoopbackNamespaceFixtures(unittest.TestCase):
    """Actual namespace/nft probes, separate from the host tool receipt fixture."""

    def test_kernel_namespace_nft_rules_allow_exact_role_and_deny_peer_routes(self):
        generation_digest = "a" * 64
        registry = None
        lease = None
        try:
            candidate_uids = (17001, 17002, 17003)
            active_uids: set[int] = set()
            for status_path in Path("/proc").glob("[0-9]*/status"):
                try:
                    uid_line = next(line for line in status_path.read_text().splitlines()
                                    if line.startswith("Uid:"))
                    active_uids.add(int(uid_line.split()[1]))
                except (OSError, StopIteration, ValueError, IndexError):
                    continue
            if any(uid in active_uids for uid in candidate_uids):
                self.skipTest("reserved fixture service UID is currently active")
            for uid in candidate_uids:
                try:
                    pwd.getpwuid(uid)
                except KeyError:
                    continue
                self.skipTest("reserved fixture service UID already has an account")
            services = [
                _service("display", "display-profile", "display-v1", candidate_uids[0]),
                _service("gateway", "gateway-profile", "gateway-v1", candidate_uids[1]),
                _service("desktop", "desktop-profile", "desktop-v1", candidate_uids[2]),
            ]
            record = {
                "id": "linux-fixture-network", "generation": "linux-fixture-v1",
                "namespace_identity": "linux-fixture-session",
                "member_enrollment_ids": ["display", "gateway", "desktop"],
                "listener_bindings": [{"enrollment_id": "display", "role": "xpra-display",
                                       "ipv4": "127.0.0.1", "port": 14500}],
                "client_bindings": [{"enrollment_id": "gateway", "listener_enrollment_id": "display",
                                     "port": 14500}],
                "policy_artifact_id": POLICY_ID, "policy_sha256": POLICY_SHA256,
            }
            network, = validate_private_loopback_networks([record], services, generation_digest)
            registry = HostToolObservationRegistry.for_linux_fixture()
            observation_handle = registry.observe_selected_nft_tool(network)
            tool = registry.resolve_selected_nft_tool(observation_handle, network)
            observation = registry._observations[observation_handle]
            witness_path = Path(observation.signed_index_records[0]["packages_path"])
            witness_fd = os.open(witness_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                original = os.pread(witness_fd, 1, 0)
                self.assertEqual(len(original), 1)
                os.pwrite(witness_fd, bytes((original[0] ^ 1,)), 0)
                os.fsync(witness_fd)
                with self.assertRaises(HostToolObservationDenied):
                    tool.verify_current()
                os.pwrite(witness_fd, original, 0)
                os.fsync(witness_fd)
            finally:
                os.close(witness_fd)
            tool.verify_current()
            stale = replace(observation, expires_monotonic=time.monotonic() - 1)
            registry._observations[observation_handle] = stale
            with self.assertRaises(HostToolObservationDenied):
                tool.verify_current()
            registry._observations[observation_handle] = observation
            tool.verify_current()
            lease = create_root_namespace(network, tool)
            try:
                self.assertEqual(lease.namespace_path, namespace_path_for(network))
                self.assertNotEqual(lease.namespace_inode, os.stat("/proc/self/ns/net").st_ino)
                verify_root_network_lease(lease)

                host_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                host_probe.bind(("127.0.0.1", 0))
                host_probe.listen(1)
                host_port = host_probe.getsockname()[1]

                original_ns = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                failure: list[BaseException] = []

                def probes() -> None:
                    try:
                        os.setns(lease.namespace_fd, getattr(os, "CLONE_NEWNET", 0x40000000))
                        server, _ = _start_listener(candidate_uids[0], "127.0.0.1", 14500)
                        self.assertEqual(_client(candidate_uids[1], "127.0.0.1", 14500, True), 0)
                        self.assertEqual(_wait(server), 0)

                        wrong_uid_server, _ = _start_listener(candidate_uids[0], "127.0.0.1", 14500)
                        self.assertEqual(_client(candidate_uids[2], "127.0.0.1", 14500, False), 0)
                        self.assertEqual(_wait(wrong_uid_server), 0)

                        wrong_port_server, _ = _start_listener(candidate_uids[0], "127.0.0.1", 14501)
                        self.assertEqual(_client(candidate_uids[1], "127.0.0.1", 14501, False), 0)
                        self.assertEqual(_wait(wrong_port_server), 0)

                        wrong_address_server, _ = _start_listener(candidate_uids[0], "0.0.0.0", 14500)
                        self.assertEqual(_client(candidate_uids[1], "127.0.0.2", 14500, False), 0)
                        self.assertEqual(_wait(wrong_address_server), 0)

                        # A real host-namespace listener is not visible from the held loopback netns.
                        self.assertEqual(_client(candidate_uids[1], "127.0.0.1", host_port, False), 0)
                        outside = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        outside.settimeout(.25)
                        with self.assertRaises(OSError):
                            outside.connect(("192.0.2.1", 443))
                        outside.close()
                        ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        ipv6.settimeout(.25)
                        with self.assertRaises(OSError):
                            ipv6.connect(("::1", 14500))
                        ipv6.close()
                    except BaseException as exc:
                        failure.append(exc)
                    finally:
                        try:
                            os.setns(original_ns, getattr(os, "CLONE_NEWNET", 0x40000000))
                        except BaseException as exc:
                            failure.append(exc)

                worker = threading.Thread(target=probes, name="private-loopback-probes")
                worker.start()
                worker.join(20.0)
                os.close(original_ns)
                host_probe.close()
                self.assertFalse(worker.is_alive(), "private namespace probes exceeded their fixed bound")
                if failure:
                    raise failure[0]

                # These are real systemd transient services. A successful
                # exact bind plus denied wrong-port/client binds demonstrates
                # the manager attached functioning bind4 cgroup BPF programs;
                # a show-property string alone would not establish that.
                bind_ok = _systemd_bind_probe(lease.namespace_path, candidate_uids[0], 14500,
                                              allowed=True, allowed_port=14500)
                self.assertEqual(bind_ok.returncode, 0, bind_ok.stdout)
                self.assertIn("BOUND", bind_ok.stdout)
                wrong_port = _systemd_bind_probe(lease.namespace_path, candidate_uids[0], 14501,
                                                 allowed=False, allowed_port=14500)
                self.assertEqual(wrong_port.returncode, 0, wrong_port.stdout)
                self.assertIn("DENIED:", wrong_port.stdout)
                client_bind = _systemd_bind_probe(lease.namespace_path, candidate_uids[1], 0,
                                                  allowed=False, allowed_port=None)
                self.assertEqual(client_bind.returncode, 0, client_bind.stdout)
                self.assertIn("DENIED:", client_bind.stdout)
            finally:
                close_root_network_lease(lease)
        finally:
            if lease is not None:
                lease.close_fd()
            if registry is not None:
                registry.close()


if __name__ == "__main__":
    unittest.main()
