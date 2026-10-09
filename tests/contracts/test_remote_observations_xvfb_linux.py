"""Disposable Linux Xvfb/XRes kernel fixture for the root window observer.

This test proves only real X server peer credentials, XRes server-reported local
client PIDs, PIDFD liveness, procfs executable/cgroup identity, and a bounded
tile hash. It is deliberately not a Hermes package, active enrollment, or Pi
acceptance test. The selected root Xauthority startup receipt and full observer
join have separate tests once that protected receipt registry is installed.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import pwd
import secrets
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.remote_observations import (
    RemoteObservationUnavailable,
    _check_xserver_peer,
    _hash_bounded_window_sample,
    _owner_pid,
    _proc_starttime,
    _read_xauthority,
    _x_descendants,
    _xopen_authorized_display,
    _xres_client_pids,
    _xroot_window,
    _xwindow_viewable,
    SelectedNativeWindow,
)


def _field(value: bytes) -> bytes:
    return struct.pack(">H", len(value)) + value


def _start_client(display_name: str, xauthority: str, x: int) -> subprocess.Popen[str]:
    source = r'''
import ctypes, ctypes.util, os, sys, time
x11 = ctypes.CDLL(ctypes.util.find_library("X11"))
x11.XOpenDisplay.argtypes=[ctypes.c_char_p]; x11.XOpenDisplay.restype=ctypes.c_void_p
x11.XDefaultRootWindow.argtypes=[ctypes.c_void_p]; x11.XDefaultRootWindow.restype=ctypes.c_ulong
x11.XCreateSimpleWindow.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_ulong,ctypes.c_ulong]
x11.XCreateSimpleWindow.restype=ctypes.c_ulong
x11.XMapWindow.argtypes=[ctypes.c_void_p,ctypes.c_ulong]; x11.XMapWindow.restype=ctypes.c_int
x11.XSync.argtypes=[ctypes.c_void_p,ctypes.c_int]; x11.XSync.restype=ctypes.c_int
d=x11.XOpenDisplay(None)
if not d: raise SystemExit("fixture XOpenDisplay failed")
root=x11.XDefaultRootWindow(d)
w=x11.XCreateSimpleWindow(d,root,int(sys.argv[1]),20,180,100,0,0,0x336699)
x11.XMapWindow(d,w); x11.XSync(d,0)
print(int(w),flush=True)
time.sleep(20)
'''
    environment = {"PATH": "/usr/bin:/bin", "DISPLAY": display_name,
                   "XAUTHORITY": xauthority, "HOME": "/root", "LANG": "C"}
    process = subprocess.Popen(["/usr/bin/python3", "-I", "-c", source, str(x)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, close_fds=True, env=environment)
    assert process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], 4.0)
    if not ready:
        process.kill()
        raise AssertionError("real X11 client did not map its window")
    xid_line = process.stdout.readline().strip()
    if not xid_line.isdecimal():
        stderr = process.stderr.read() if process.stderr else ""
        process.kill()
        raise AssertionError(f"real X11 client did not return its mapped XID: {stderr[:300]}")
    process._fixture_window_xid = int(xid_line)  # type: ignore[attr-defined]
    return process


@unittest.skipUnless(
    os.environ.get("HERMES_RUN_XVFB_PROOF") == "1"
    and os.name == "posix" and Path("/proc/self/stat").exists()
    and os.geteuid() == 0 and hasattr(os, "pidfd_open"),
    "requires the explicit root Linux Xvfb/XRes workflow fixture",
)
class RemoteObservationXvfbKernelProof(unittest.TestCase):
    def test_real_xres_client_pid_pidfd_and_bounded_window_tile(self) -> None:
        xvfb = shutil.which("Xvfb")
        x11_name = ctypes.util.find_library("X11")
        xres_name = ctypes.util.find_library("XRes") or ctypes.util.find_library("Xres")
        if not xvfb or not x11_name or not xres_name:
            self.skipTest("pinned Xvfb, libX11, and XRes packages are required")

        cookie = os.urandom(16)
        server: subprocess.Popen[bytes] | None = None
        clients: list[subprocess.Popen[str]] = []
        display: int | None = None
        raw_cookie = bytearray(cookie)
        with tempfile.TemporaryDirectory(prefix="hermes-xres-fixture-") as directory:
            auth_path = Path(directory) / "authority"
            hostname = socket.gethostname().encode("ascii", "ignore")
            candidates = [100 + secrets.randbelow(500) for _ in range(64)]
            display_number = next((str(number) for number in candidates
                if not Path(f"/tmp/.X11-unix/X{number}").exists()
                and not Path(f"/tmp/.X{number}-lock").exists()), None)
            if display_number is None:
                self.skipTest("no unused disposable local X display number")
            display_name = f":{display_number}"
            auth_record = (struct.pack(">H", 256) + _field(hostname)
                           + _field(display_number.encode("ascii"))
                           + _field(b"MIT-MAGIC-COOKIE-1") + _field(cookie))
            auth_path.write_bytes(auth_record)
            auth_path.chmod(0o600)
            server = subprocess.Popen([xvfb, display_name, "-screen", "0", "640x480x24",
                "-auth", str(auth_path), "-nolisten", "tcp", "-noreset"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True)
            try:
                socket_path = Path(f"/tmp/.X11-unix/X{display_number}")
                deadline = time.monotonic() + 5.0
                while (time.monotonic() < deadline and not socket_path.exists()
                       and server.poll() is None):
                    time.sleep(0.01)
                if not socket_path.exists():
                    self.fail("Xvfb did not allocate a local display")
                row = SelectedNativeWindow(
                    remote_enrollment_id="fixture-only", native_profile_id="fixture-only",
                    native_generation="fixture-only", native_uid=os.getuid(),
                    native_cgroup_id="fixture-only", allowed_executable_sha256s=("0" * 64,),
                    display_server_profile_id="fixture-only", display_server_generation="fixture-only",
                    display_name=display_name, xauthority_path=auth_path,
                    xauthority_device=auth_path.stat().st_dev, xauthority_inode=auth_path.stat().st_ino,
                    xauthority_uid=auth_path.stat().st_uid)
                root_cookie = _read_xauthority(row, display_number)
                x11, xres = ctypes.CDLL(x11_name), ctypes.CDLL(xres_name)
                display = _xopen_authorized_display(x11, display_name, root_cookie)
                for index in range(len(root_cookie)):
                    root_cookie[index] = 0

                clients.append(_start_client(display_name, str(auth_path), 20))
                clients.append(_start_client(display_name, str(auth_path), 240))
                server_start = _proc_starttime(server.pid)
                server_account = pwd.getpwuid(os.stat(f"/proc/{server.pid}").st_uid)
                server_identity = SimpleNamespace(pid=server.pid, uid=server_account.pw_uid,
                    gid=server_account.pw_gid, pid_starttime_ticks=server_start)
                _check_xserver_peer(x11, display, server_identity)

                try:
                    clients_by_xid = _xres_client_pids(x11, xres, display)
                except RemoteObservationUnavailable as exc:
                    self.skipTest(
                        "Xvfb advertised XRes 1.2 but did not provide a usable server-derived "
                        f"local client PID response: {exc}")
                windows = [xid for xid in _x_descendants(x11, display, _xroot_window(x11, display))
                           if _xwindow_viewable(x11, display, xid)]
                self.assertGreaterEqual(len(windows), 2)
                actual_owners: dict[int, int] = {}
                for xid in windows:
                    owner = _owner_pid(xid, clients_by_xid)
                    if owner is not None:
                        actual_owners[xid] = owner
                selected_xid = clients[0]._fixture_window_xid  # type: ignore[attr-defined]
                foreign_xid = clients[1]._fixture_window_xid  # type: ignore[attr-defined]
                self.assertEqual(actual_owners[selected_xid], clients[0].pid)
                self.assertEqual(actual_owners[foreign_xid], clients[1].pid)
                self.assertNotEqual(actual_owners[selected_xid], actual_owners[foreign_xid])

                for client in clients:
                    pidfd = os.pidfd_open(client.pid, 0)
                    try:
                        poller = select.poll()
                        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                        self.assertEqual(poller.poll(0), [])
                        self.assertGreater(_proc_starttime(client.pid), 0)
                        exe_path = os.readlink(f"/proc/{client.pid}/exe")
                        self.assertTrue(exe_path.startswith("/usr/bin/python"))
                        cgroup = Path(f"/proc/{client.pid}/cgroup").read_bytes()
                        self.assertTrue(cgroup)
                        self.assertEqual(hashlib.sha256(Path(exe_path).read_bytes()).hexdigest(),
                                         hashlib.sha256(Path("/usr/bin/python3").read_bytes()).hexdigest())
                    finally:
                        os.close(pidfd)
                tile_digest = _hash_bounded_window_sample(x11, display, selected_xid)
                self.assertRegex(tile_digest, r"^[0-9a-f]{64}$")

                stale_pid, stale_xid = clients[1].pid, foreign_xid
                clients[1].terminate()
                clients[1].wait(timeout=3)
                stale_pidfd = os.pidfd_open(stale_pid, 0)
                try:
                    poller = select.poll()
                    poller.register(stale_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                    self.assertTrue(poller.poll(0), "exited XRes client PIDFD must report stale")
                    self.assertIn(stale_xid, windows)
                finally:
                    os.close(stale_pidfd)
            finally:
                if display is not None:
                    x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
                    x11.XCloseDisplay.restype = ctypes.c_int
                    x11.XCloseDisplay(display)
                for client in clients:
                    if client.poll() is None:
                        client.terminate()
                    try:
                        client.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        client.kill(); client.wait(timeout=2)
                if server is not None:
                    server.terminate()
                    try:
                        server.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        server.kill(); server.wait(timeout=2)
            for index in range(len(raw_cookie)):
                raw_cookie[index] = 0


if __name__ == "__main__":
    unittest.main()
