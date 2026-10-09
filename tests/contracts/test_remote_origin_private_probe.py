from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from hermes_installer.authority.remote_origin import (
    ActiveCatalogControlSocketResolver,
    CustodyRemoteOriginProcessManager,
    HMACReceiptSigner,
    KernelOriginEvidence,
    RemoteOriginCallerIdentity,
    RemoteOriginControlSocketResolver,
    RemoteOriginDenied,
    RemoteOriginProbeBinding,
    RemoteSetupWriterBinding,
    SelectedRemoteOrigin,
    SelectedRemoteOriginControlSocket,
    SelectedRemoteOriginProbeAuthority,
    VerifiedRemoteSetupTransaction,
    verify_origin_receipt,
    verify_selected_remote_origin,
)


_ACCOUNT = "699d98642c564d2e855e9661899b7252"
_TUNNEL = "c1744f8b-faa1-48a4-9e5c-02ac921467fa"
_OBSERVATIONS = {
    "loopback_only", "unauthenticated_denied", "authorized_asset_served",
    "authorized_websocket_attached", "official_desktop_window_observed",
    "arbitrary_route_denied", "shell_route_denied", "full_host_desktop_denied",
}


class _Catalog:
    def __init__(self, selected, binding):
        self.selected = selected
        self.binding = binding

    def selected_origin(self, enrollment_id):
        return self.selected if enrollment_id == self.selected.enrollment_id else None

    def selected_origin_control_socket(self, socket_id):
        return self.binding if socket_id == "control-socket" else None


class _Custody:
    def __init__(self, proofs):
        self.proofs = proofs

    def inspect_enrolled_process(self, profile_id, generation):
        proof = self.proofs.get((profile_id, generation))
        if proof is None or proof.expires_monotonic <= __import__("time").monotonic():
            return None
        return proof


class _Caller:
    def __init__(self, identity):
        self.identity = identity

    def current(self):
        return self.identity


class _TransactionVerifier:
    def __init__(self, transaction):
        self.transaction = transaction

    def verify_origin_probe_transaction(self, handle, selected, caller):
        if handle != "S" * 43:
            raise PermissionError("not the active setup transaction")
        return self.transaction


def _read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


class _AppSocketFixture:
    """Actual loopback HTTP/Upgrade exchanges; observations are derived from bytes."""
    def __init__(self):
        self.asset_enabled = True
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.address = self.listener.getsockname()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, peer = self.listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                raw = bytearray()
                while b"\r\n\r\n" not in raw and len(raw) < 8192:
                    part = conn.recv(1024)
                    if not part:
                        break
                    raw.extend(part)
                request = bytes(raw)
                first = request.split(b"\r\n", 1)[0]
                authorized = b"X-Setup-Probe: " in request
                if not peer[0].startswith("127."):
                    status, body = b"403 Forbidden", b"denied"
                elif first.startswith(b"GET /client/index.html ") and authorized and self.asset_enabled:
                    status, body = b"200 OK", b"hermes-official-desktop-asset-v1"
                elif first.startswith(b"GET /client/stream ") and authorized and b"Upgrade: websocket" in request:
                    conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                 b"Connection: Upgrade\r\n\r\n")
                    conn.sendall(b"HERMES_NATIVE_WINDOW_FRAME:fixture-1")
                    continue
                elif first.startswith(b"GET /client/bootstrap.html "):
                    status, body = b"401 Unauthorized", b"denied"
                else:
                    status, body = b"404 Not Found", b"denied"
                conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


class _PrivateControlFixture:
    """Root-private socket fixture which performs fixed finite HTTP/WS probes."""
    def __init__(self, path, app):
        self.path = path
        self.app = app
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        os.chmod(path, 0o600)
        self.listener.listen(4)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _exchange(self, path, *, challenge=None, websocket=False):
        with socket.create_connection(self.app.address, timeout=2) as conn:
            headers = b"GET " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
            if challenge is not None:
                headers += b"X-Setup-Probe: " + challenge.encode("ascii") + b"\r\n"
            if websocket:
                headers += b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            conn.sendall(headers + b"\r\n")
            conn.settimeout(2)
            response = bytearray()
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > 8192:
                    raise AssertionError("fixture origin response exceeded its read bound")
            return bytes(response)

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                try:
                    size = struct.unpack("!I", _read_exact(conn, 4))[0]
                    if not 1 <= size <= 65536:
                        continue
                    request = json.loads(_read_exact(conn, size))
                    challenge = request["challenge"]
                    asset = self._exchange(b"/client/index.html", challenge=challenge)
                    unauth = self._exchange(b"/client/bootstrap.html")
                    ws = self._exchange(b"/client/stream", challenge=challenge, websocket=True)
                    arbitrary = self._exchange(b"/random-route")
                    shell = self._exchange(b"/shell")
                    desktop = self._exchange(b"/desktop")
                    frame = ws.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in ws else b""
                    statuses = {
                        "loopback_only": True,
                        "unauthenticated_denied": unauth.startswith(b"HTTP/1.1 401"),
                        "authorized_asset_served": asset.startswith(b"HTTP/1.1 200") and b"hermes-official-desktop-asset-v1" in asset,
                        "authorized_websocket_attached": ws.startswith(b"HTTP/1.1 101") and bool(frame),
                        "official_desktop_window_observed": frame.startswith(b"HERMES_NATIVE_WINDOW_FRAME:"),
                        "arbitrary_route_denied": arbitrary.startswith(b"HTTP/1.1 404"),
                        "shell_route_denied": shell.startswith(b"HTTP/1.1 404"),
                        "full_host_desktop_denied": desktop.startswith(b"HTTP/1.1 404"),
                    }
                    response = {key: request[key] for key in (
                        "schema", "probe_handle", "sequence", "challenge", "request_digest",
                        "remote_enrollment_id", "gateway_profile_id", "gateway_generation",
                        "native_profile_id", "desktop_generation", "connector_target_id",
                        "policy_config_digest", "policy_revision", "service_generation_digest")}
                    response.update(operation="probe_selected_origin_result", observations=statuses,
                        observed_assertion_ids=["fixture:loopback-http", "fixture:websocket-upgrade", "fixture:native-frame"],
                        asset_content_sha256=hashlib.sha256(b"hermes-official-desktop-asset-v1").hexdigest(),
                        websocket_observation_id=hashlib.sha256(ws + challenge.encode()).hexdigest()[:32],
                        native_window_observation_id=hashlib.sha256(frame + challenge.encode()).hexdigest()[:32])
                    payload = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
                    conn.sendall(struct.pack("!I", len(payload)) + payload)
                except Exception:
                    continue

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


class RemoteOriginPrivateProbeTests(unittest.TestCase):
    def test_root_readiness_requires_real_private_http_websocket_and_window_exchange(self):
        # /tmp is sticky and world-writable on Linux, so a 0700 child there
        # still has an unsafe ancestor for the production fd-walk check. macOS
        # uses its per-user private temp hierarchy instead of the /private/tmp
        # integration checkout, whose ancestor is intentionally world-writable.
        parent = None if sys.platform == "darwin" else Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(dir=parent) as temp:
            base = Path(temp).resolve()
            os.chmod(base, 0o700)
            app = _AppSocketFixture()
            socket_path = base / "origin.sock"
            control = _PrivateControlFixture(socket_path, app)
            try:
                now = __import__("time").monotonic
                expires = now() + 120
                setup_handle = "S" * 43
                caller = RemoteOriginCallerIdentity(os.getuid(), os.getpid(), 1, "setup", "setup-gen",
                    "a" * 64, "setup-cgroup", "setup-pidfd", expires)
                setup_binding = RemoteSetupWriterBinding("setup", "setup-gen", "setup-role",
                    "a" * 64, "setup-enrollment", "setup-policy", ("tunnel-enrollment",),
                    "writer-enrollment", "probe-enrollment")
                probe_binding = RemoteOriginProbeBinding("probe", "probe-gen", "probe-role",
                    "d" * 64, "probe-enrollment", "control-socket")
                selected = SelectedRemoteOrigin("remote-enrollment", "gateway-gen", "desktop-gen",
                    "xpra-native", "b" * 64, "policy-r1", "c" * 64,
                    "desktop.example.test", "https://desktop.example.test", True,
                    "gateway", "gateway-enrollment", "e" * 64, "native", "native-enrollment",
                    setup_binding, probe_binding)
                st = socket_path.lstat()
                selected_socket = SelectedRemoteOriginControlSocket(socket_path, st.st_dev, st.st_ino,
                    st.st_uid, "gateway", "gateway-gen")
                catalog = _Catalog(selected, selected_socket)

                class CustodyProofs:
                    def __init__(self):
                        self.by_profile = {}
                    def inspect_enrolled_process(self, profile_id, generation):
                        return self.by_profile.get((profile_id, generation))

                custody = CustodyProofs()
                def add_proof(profile, enrollment, generation, sha):
                    custody.by_profile[(profile, generation)] = type("Proof", (), dict(
                        process_id=f"process-{profile}", enrollment_id=enrollment, profile_id=profile,
                        profile_generation=generation, uid=os.getuid(), gid=os.getgid(), pid=os.getpid(),
                        pid_starttime_ticks=10, executable_device=1, executable_inode=1,
                        executable_sha256=sha, cgroup_id=f"cgroup-{profile}",
                        mount_namespace_inode=1, network_namespace_inode=1,
                        pidfd_registry_handle=f"pidfd-{profile}", expires_monotonic=expires))()
                add_proof("gateway", "gateway-enrollment", "gateway-gen", "e" * 64)
                add_proof("native", "native-enrollment", "desktop-gen", "f" * 64)
                add_proof("probe", "probe-enrollment", "probe-gen", "d" * 64)
                tx = VerifiedRemoteSetupTransaction(
                    hashlib.sha256(setup_handle.encode()).hexdigest(), "remote-enrollment",
                    "tunnel-enrollment", _ACCOUNT, _TUNNEL, "tunnel-gen", "setup", "setup-gen",
                    "setup-role", "setup-enrollment", "a" * 64, "setup-policy", "writer-enrollment",
                    "probe-enrollment", ("tunnel-enrollment",), caller.digest(), "N" * 32,
                    hashlib.sha256(b"setup-response").hexdigest(), now(), now() + 20)
                signer = HMACReceiptSigner(b"R" * 32)
                process_manager = CustodyRemoteOriginProcessManager(custody)
                authority = SelectedRemoteOriginProbeAuthority(
                    catalog=catalog, setup_transactions=_TransactionVerifier(tx), current_peer=_Caller(caller),
                    process_manager=process_manager, custody=custody,
                    socket_resolver=ActiveCatalogControlSocketResolver(catalog), signer=signer,
                    peer_credentials=lambda _sock: (os.getpid(), os.getuid(), os.getgid()))
                handle = authority.issue_selected_origin_probe("remote-enrollment", setup_handle)
                observed = authority.probe_selected_app(selected, handle)
                self.assertEqual(set(observed), _OBSERVATIONS)
                self.assertTrue(all(observed.values()))
                readiness = verify_selected_remote_origin("remote-enrollment", catalog=catalog,
                    process_manager=process_manager, gateway_probe=authority,
                    root_probe_handle=handle, signer=signer)
                self.assertTrue(verify_origin_receipt(readiness, signer,
                    selected_enrollment_id="remote-enrollment",
                    expected_probe_receipt_handle=observed.probe_receipt_handle))
                with self.assertRaises(RemoteOriginDenied):
                    authority.probe_selected_app(selected, handle)
                app.asset_enabled = False
                denied_handle = authority.issue_selected_origin_probe("remote-enrollment", setup_handle)
                with self.assertRaises(RemoteOriginDenied):
                    authority.probe_selected_app(selected, denied_handle)
            finally:
                control.close()
                app.close()


if __name__ == "__main__":
    unittest.main()
