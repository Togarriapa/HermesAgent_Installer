from __future__ import annotations

import hashlib
import fcntl
import json
import os
import platform
import pwd
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from hermes_installer.authority.private_loopback_network import (
    POLICY_ID, POLICY_SHA256, close_root_network_lease,
    create_root_namespace, namespace_path_for, validate_private_loopback_networks, _in_namespace,
    verify_root_network_lease, PrivateLoopbackMember, retain_network_member,
    _subject_capability_receipt,
    release_network_member, unit_network_properties,
)
from hermes_installer.authority.host_tool_observation import (
    HostToolObservationDenied, HostToolObservationRegistry,
)
from hermes_installer.authority.types import AuthorityDenied


def test_subject_capability_observation_requires_empty_inheritable_capabilities(monkeypatch):
    status = "\n".join((
        "CapEff:\t0000000000000000", "CapPrm:\t0000000000000000",
        "CapBnd:\t0000000000000000", "CapAmb:\t0000000000000000",
        "CapInh:\t0000000000000001",
    ))

    def read_text(path, *args, **kwargs):
        assert str(path) == "/proc/123/status"
        return status

    monkeypatch.setattr(Path, "read_text", read_text)
    with unittest.TestCase().assertRaises(AuthorityDenied):
        _subject_capability_receipt(123)


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


def _toggle_interface(namespace_fd: int, name: str, up: bool) -> None:
    host_fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    failure: list[BaseException] = []

    def change() -> None:
        try:
            os.setns(namespace_fd, getattr(os, "CLONE_NEWNET", 0x40000000))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
            try:
                request = struct.pack("16sH14s", name.encode("ascii"), 0, b"")
                flags = struct.unpack("16sH14s", fcntl.ioctl(sock.fileno(), 0x8913, request))[1]
                next_flags = flags | 1 if up else flags & ~1
                fcntl.ioctl(sock.fileno(), 0x8914, struct.pack("16sH14s", name.encode("ascii"), next_flags, b""))
            finally:
                sock.close()
        except BaseException as exc:
            failure.append(exc)
        finally:
            try:
                os.setns(host_fd, getattr(os, "CLONE_NEWNET", 0x40000000))
            except BaseException as exc:
                failure.append(exc)

    thread = threading.Thread(target=change, name="loopback-template-mutation")
    thread.start(); thread.join(5.0)
    os.close(host_fd)
    if thread.is_alive() or failure:
        raise failure[0] if failure else AssertionError("template state mutation timed out")


def _systemd_bind_probe(namespace: Path, uid: int, port: int, *, allowed: bool,
                        allowed_port: int | None) -> subprocess.CompletedProcess[str]:
    """Run an actual transient unit so systemd attaches its cgroup bind BPF."""
    unit = "hermes-loopback-bind-" + uuid.uuid4().hex + ".service"
    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    probe = (
        "import pathlib,socket,sys; "
        "st={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line}; "
        "caps=[int(st[k],16) for k in ('CapEff','CapPrm','CapBnd','CapAmb')]; "
        "print('CAPS_EMPTY' if not any(caps) else 'CAPS_PRESENT'); "
        "sys.exit(41) if any(caps) or pathlib.Path('/dev/net/tun').exists() else None; "
        "print('TUN_DEVICE_HIDDEN'); s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); "
        "\ntry:\n s.bind(('127.0.0.1',int(sys.argv[1]))); print('BOUND'); sys.exit(0 if sys.argv[2]=='allow' else 31)"
        "\nexcept OSError as e:\n print('DENIED:'+str(e)); sys.exit(0 if sys.argv[2]=='deny' else 32)"
    )
    command = [
        "/usr/bin/systemd-run", "--system", "--quiet", "--wait", "--pipe", "--collect",
        "--unit=" + unit, "--property=Type=exec", "--property=User=" + str(uid),
        "--property=NetworkNamespacePath=" + str(namespace),
        "--property=SocketBindDeny=any",
        "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
        "--property=PrivateDevices=yes", "--property=DevicePolicy=closed",
        "--property=NoNewPrivileges=yes",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET",
    ]
    if allowed_port is not None:
        command.append(f"--property=SocketBindAllow=ipv4:tcp:{allowed_port}")
    command.extend(("/usr/bin/python3", "-c", probe, str(port), "allow" if allowed else "deny"))
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=15, check=False)
    if result.returncode != 0:
        result.stdout += _systemd_bind_probe_diagnostics(unit, started_utc)
    return result


def _systemd_bind_probe_diagnostics(unit: str, started_utc: str) -> str:
    """Append bounded host/unit evidence only when the kernel probe fails."""
    output = [f"\nBIND_PROBE_DIAGNOSTICS unit={unit} started_utc={started_utc}\n"]

    def capture(label: str, argv: tuple[str, ...], *, limit: int = 4096) -> str:
        try:
            result = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=3, check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            detail = f"unavailable ({type(exc).__name__})"
        else:
            detail = result.stdout[:limit]
            if not detail:
                detail = f"<empty; exit={result.returncode}>"
            elif result.returncode:
                detail += f"\n<exit={result.returncode}>"
        output.append(f"[{label}]\n{detail}\n")
        return detail

    capture("uname", ("/usr/bin/uname", "-a"))
    capture("systemd-version", ("/usr/bin/systemctl", "--version"))
    capture("cgroup2-mount", ("/usr/bin/findmnt", "--noheadings", "--output",
                               "FSTYPE,OPTIONS", "--target", "/sys/fs/cgroup"))
    try:
        controllers = Path("/sys/fs/cgroup/cgroup.controllers").read_text(encoding="ascii")[:1024]
    except OSError as exc:
        controllers = f"unavailable ({type(exc).__name__})"
    output.append(f"[cgroup2-controllers]\n{controllers}\n")

    properties = capture(
        "transient-unit-properties",
        ("/usr/bin/systemctl", "show", unit, "--no-pager",
         "--property=ControlGroup", "--property=SocketBindDeny",
         "--property=SocketBindAllow", "--property=Result",
         "--property=ExecMainStatus"),
    )
    cgroup = next((line.partition("=")[2] for line in properties.splitlines()
                   if line.startswith("ControlGroup=")), "")
    if not cgroup or not cgroup.startswith("/"):
        output.append(
            "[cgroup-bind-attachments]\n"
            "unavailable (ControlGroup not reported after --collect)\n"
        )
    else:
        bpftool = next((path for path in (Path("/usr/sbin/bpftool"), Path("/usr/bin/bpftool"))
                        if path.is_file()), None)
        cgroup_path = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        if bpftool is None:
            output.append(
                "[cgroup-bind-attachments]\nunavailable (bpftool is not installed)\n"
            )
        elif not cgroup_path.is_dir():
            output.append(
                "[cgroup-bind-attachments]\n"
                "unavailable (transient unit cgroup absent after --collect)\n"
            )
        else:
            capture("cgroup-bind-attachments", (str(bpftool), "cgroup", "show", str(cgroup_path)))

    capture("unit-journal", ("/usr/bin/journalctl", "--unit", unit,
                              "--since", started_utc, "--no-pager",
                              "--output=short-iso-precise", "--lines=80"), limit=8192)
    diagnostics = "".join(output)
    return diagnostics[:20_000] + ("\n<diagnostics truncated>\n" if len(diagnostics) > 20_000 else "")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and Path("/usr/sbin/nft").exists(),
                     "requires root Linux, nftables and private-netns kernel support")
class LinuxPrivateLoopbackNamespaceFixtures(unittest.TestCase):
    """Actual namespace/nft probes, separate from the host tool receipt fixture."""

    def test_kernel_namespace_nft_rules_allow_exact_role_and_deny_peer_routes(self):
        generation_digest = "a" * 64
        registry = None
        lease = None
        fixture_users: list[str] = []
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
            useradd = Path("/usr/sbin/useradd")
            userdel = Path("/usr/sbin/userdel")
            systemctl = Path("/usr/bin/systemctl")
            if (not useradd.is_file() or not userdel.is_file()
                    or not systemctl.is_file() or not Path("/usr/bin/systemd-run").is_file()):
                self.skipTest("fixture-only system account tools are unavailable")
            if subprocess.run([str(systemctl), "--system", "show-environment"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=3, check=False).returncode:
                self.skipTest("systemd system manager is unavailable")
            fixture_suffix = uuid.uuid4().hex[:12]
            for index, uid in enumerate(candidate_uids):
                username = f"hermes-net-{fixture_suffix}-{index}"
                created = subprocess.run(
                    [str(useradd), "--system", "--no-create-home", "--home-dir=/nonexistent",
                     "--shell=/usr/sbin/nologin", "--user-group", "--uid", str(uid), username],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, text=True, timeout=5, check=False,
                )
                if created.returncode:
                    self.fail("could not create fixture-only identities required by systemd")
                fixture_users.append(username)
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

                template_state = json.loads(_in_namespace(lease.namespace_fd, "netns", tool))
                optional_links = [row for row in template_state["links"] if row["name"] != "lo"]
                if optional_links:
                    template_name = optional_links[0]["name"]
                    _toggle_interface(lease.namespace_fd, template_name, True)
                    with self.assertRaises(AuthorityDenied):
                        verify_root_network_lease(lease)
                    _toggle_interface(lease.namespace_fd, template_name, False)
                    verify_root_network_lease(lease)

                # Run the bind probes before any packet is sent to 127.0.0.1:14500.
                # The later successful TCP exchange leaves that exact tuple in
                # TIME_WAIT, which can make a second bind fail with EADDRINUSE.
                bind_ok = _systemd_bind_probe(lease.namespace_path, candidate_uids[0], 14500,
                                              allowed=True, allowed_port=14500)
                self.assertEqual(bind_ok.returncode, 0, bind_ok.stdout)
                self.assertIn("BOUND", bind_ok.stdout)
                self.assertIn("CAPS_EMPTY", bind_ok.stdout)
                self.assertIn("TUN_DEVICE_HIDDEN", bind_ok.stdout)
                wrong_port = _systemd_bind_probe(lease.namespace_path, candidate_uids[0], 14501,
                                                 allowed=False, allowed_port=14500)
                self.assertEqual(wrong_port.returncode, 0, wrong_port.stdout)
                self.assertIn("DENIED:", wrong_port.stdout)
                client_bind = _systemd_bind_probe(lease.namespace_path, candidate_uids[1], 0,
                                                  allowed=False, allowed_port=None)
                self.assertEqual(client_bind.returncode, 0, client_bind.stdout)
                self.assertIn("DENIED:", client_bind.stdout)
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
                verify_root_network_lease(lease)

                member = PrivateLoopbackMember(network, "display", candidate_uids[0], generation_digest)
                unit = "hermes-installer-" + uuid.uuid4().hex + ".service"
                started = False
                proof = None
                subject_pidfd = -1
                cgroup = "/system.slice/" + unit
                try:
                    launch = ["/usr/bin/systemd-run", "--system", "--quiet", "--unit=" + unit,
                              "--property=Type=exec", "--property=User=" + str(candidate_uids[0])]
                    launch.extend(unit_network_properties(member, lease.namespace_path))
                    launch.extend(("/usr/bin/sleep", "60"))
                    start_result = subprocess.run(launch, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        timeout=15, check=False)
                    self.assertEqual(start_result.returncode, 0, start_result.stdout)
                    started = True
                    pid_result = subprocess.run(["/usr/bin/systemctl", "show", unit,
                        "--property=MainPID", "--value"], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        timeout=5, check=False)
                    self.assertEqual(pid_result.returncode, 0, pid_result.stdout)
                    subject_pid = int(pid_result.stdout.strip())
                    subject_pidfd = os.pidfd_open(subject_pid)
                    proof = retain_network_member(lease, member, pid=subject_pid,
                        pidfd=subject_pidfd, cgroup=cgroup, unit=unit)
                    self.assertEqual(lease.subject_capability_receipt_handles["display"],
                                     proof.capability_receipt_sha256)
                    verify_root_network_lease(lease)
                finally:
                    if started:
                        subprocess.run(["/usr/bin/systemctl", "stop", unit],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=10, check=False)
                    if proof is not None:
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            try:
                                if not Path("/sys/fs/cgroup" + cgroup + "/cgroup.procs").read_text().strip():
                                    break
                            except OSError:
                                break
                            time.sleep(.05)
                        release_network_member(lease, "display")
                    if subject_pidfd >= 0:
                        os.close(subject_pidfd)
            finally:
                close_root_network_lease(lease)
        finally:
            for username in reversed(fixture_users):
                subprocess.run(["/usr/sbin/userdel", username], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=5, check=False)
            if lease is not None:
                lease.close_fd()
            if registry is not None:
                registry.close()


if __name__ == "__main__":
    unittest.main()
