from __future__ import annotations

import hashlib
import base64
import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from types import SimpleNamespace
from pathlib import Path

from hermes_installer.authority.remote_origin import (
    HMACReceiptSigner, KernelOriginEvidence, RemoteOriginDenied,
    RootOriginReadinessReceipt, SelectedRemoteOrigin, SelectedTunnel,
    CustodyRemoteOriginProcessManager, VerifiedRemoteSetupTransaction,
    verify_origin_receipt, verify_selected_remote_origin, verify_token_receipt,
    write_provisioned_tunnel_token, write_selected_tunnel_token,
)

ACCOUNT = "699d98642c564d2e855e9661899b7252"
TUNNEL = "c1744f8b-faa1-48a4-9e5c-02ac921467fa"
SETUP_HANDLE = "s" * 43


def tunnel_token(account=ACCOUNT, tunnel=TUNNEL):
    raw = json.dumps({"a": account, "t": tunnel,
                      "s": base64.b64encode(b"s" * 32).decode()}).encode()
    return base64.b64encode(raw)


def verified_setup(token, *, account=ACCOUNT, tunnel=TUNNEL):
    return VerifiedRemoteSetupTransaction(
        setup_transaction_handle_digest=hashlib.sha256(SETUP_HANDLE.encode()).hexdigest(),
        remote_enrollment_id="remote_1", tunnel_enrollment_id="te_1",
        account_id=account, tunnel_id=tunnel, generation="gen_2",
        setup_profile_id="setup", setup_generation="setup_gen",
        setup_role_artifact_id="setup_role", setup_enrollment_id="setup_enrollment",
        setup_role_sha256="c" * 64, setup_transaction_policy_id="setup_policy",
        token_writer_enrollment_id="writer_1", origin_probe_enrollment_id="probe_1",
        allowed_tunnel_enrollment_ids=("te_1",), setup_peer_identity_digest="d" * 64,
        one_use_stage_nonce="n" * 32,
        response_token_sha256=hashlib.sha256(token).hexdigest(),
        issued_monotonic=100.0, expires_monotonic=120.0)


class _Catalog:
    def __init__(self, tunnel=None, origin=None):
        self.tunnel, self.origin = tunnel, origin

    def selected_tunnel(self, enrollment_id):
        return self.tunnel

    def selected_origin(self, enrollment_id):
        return self.origin


class _Vault:
    def __init__(self, token=b"dedicated-tunnel-token-fixture"):
        self.token = token
        self.lookups = []

    def resolve_tunnel_token(self, reference_id, tunnel_id):
        self.lookups.append((reference_id, tunnel_id))
        return self.token


class _Journal:
    def __init__(self):
        self.rows = {}

    def lookup(self, enrollment_id):
        return self.rows.get(enrollment_id)

    def prepare(self, enrollment_id, entry):
        self.rows[enrollment_id] = dict(entry)
        return 1

    def record(self, enrollment_id, entry):
        self.rows[enrollment_id] = dict(entry)
        return 1


class _SocketFixtureProbe:
    """Readiness evidence comes from bounded exchanges with a real loopback socket."""
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                request = conn.recv(512)
                if b"GET /client/index.html authorized" in request:
                    status, body = b"200 OK", b"official-hermes-desktop-app"
                elif b"GET /client/stream websocket-authorized" in request:
                    status, body = b"101 Switching Protocols", b"native-window-frame"
                elif b"GET /shell" in request or b"GET /desktop" in request:
                    status, body = b"404 Not Found", b"denied"
                else:
                    status, body = b"401 Unauthorized", b"denied"
                conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)

    def _exchange(self, path):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as sock:
            sock.sendall(path + b"\r\n\r\n")
            return sock.recv(2048)

    def probe_selected_app(self, enrollment):
        asset = self._exchange(b"GET /client/index.html authorized")
        stream = self._exchange(b"GET /client/stream websocket-authorized")
        denied = self._exchange(b"GET /unauthenticated")
        shell = self._exchange(b"GET /shell")
        desktop = self._exchange(b"GET /desktop")
        return {
            "loopback_only": True,
            "unauthenticated_denied": b"401 Unauthorized" in denied,
            "authorized_asset_served": b"200 OK" in asset and b"official-hermes-desktop-app" in asset,
            "authorized_websocket_attached": b"101 Switching Protocols" in stream and b"native-window-frame" in stream,
            "official_desktop_window_observed": b"native-window-frame" in stream,
            "arbitrary_route_denied": b"401 Unauthorized" in denied,
            "shell_route_denied": b"404 Not Found" in shell,
            "full_host_desktop_denied": b"404 Not Found" in desktop,
        }

    def close(self):
        self.listener.close()
        self.thread.join(timeout=1)


class _Manager:
    def __init__(self, evidence):
        self.evidence = evidence

    def inspect_selected_origin(self, enrollment):
        return self.evidence


class _CustodyFixture:
    def inspect_enrolled_process(self, profile_id, generation):
        return SimpleNamespace(process_id="1" * 32, enrollment_id=profile_id + "-enrollment",
            profile_id=profile_id, profile_generation=generation, uid=1001, gid=1001,
            pid=42, pid_starttime_ticks=55, executable_device=1, executable_inode=2,
            executable_sha256="c" * 64, cgroup_id="cgroup-1", mount_namespace_inode=3,
            network_namespace_inode=4, pidfd_registry_handle="pidfd-handle",
            expires_monotonic=9999999999.0)


class RemoteOriginTests(unittest.TestCase):
    def test_token_writer_publishes_private_selected_token_and_signed_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve() / "tunnels"
            tunnel_dir = root / TUNNEL
            tunnel_dir.mkdir(parents=True, mode=0o700)
            os.chmod(root, 0o700)
            os.chmod(tunnel_dir, 0o700)
            token = tunnel_token()
            selected = SelectedTunnel("te_1", TUNNEL, ACCOUNT, "gen_2",
                                      "sink_1", "vault_ref_5", os.getuid(), True)
            catalog, vault, journal = _Catalog(tunnel=selected), _Vault(token), _Journal()
            signer = HMACReceiptSigner(b"s" * 32)
            receipt = write_selected_tunnel_token("te_1", catalog=catalog, vault=vault,
                token_root=root, journal=journal, signer=signer)
            path = tunnel_dir / "tunnel.token"
            self.assertEqual(path.read_bytes(), token)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertEqual(receipt.mode, 0o400)
            self.assertTrue(verify_token_receipt(receipt, signer, selected_enrollment_id="te_1"))
            self.assertNotIn(token.decode(), repr(receipt))
            self.assertNotIn(hashlib.sha256(token).hexdigest(), repr(receipt))
            again = write_selected_tunnel_token("te_1", catalog=catalog, vault=vault,
                token_root=root, journal=journal, signer=signer)
            self.assertEqual(again.file_inode, receipt.file_inode)

    def test_token_writer_refuses_preexisting_symlink_and_changed_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve() / "tunnels"
            directory = root / TUNNEL
            directory.mkdir(parents=True, mode=0o700)
            os.chmod(root, 0o700)
            os.chmod(directory, 0o700)
            (directory / "tunnel.token").symlink_to(Path(temp) / "foreign")
            selected = SelectedTunnel("te_1", TUNNEL, ACCOUNT, "gen_2",
                                      "sink_1", "vault_ref_5", os.getuid(), True)
            with self.assertRaises(RemoteOriginDenied):
                write_selected_tunnel_token("te_1", catalog=_Catalog(tunnel=selected),
                    vault=_Vault(tunnel_token()), token_root=root, journal=_Journal(),
                    signer=HMACReceiptSigner(b"s" * 32))

    def test_provisioned_response_must_match_active_account_tunnel_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve() / "tunnels"
            directory = root / TUNNEL
            directory.mkdir(parents=True, mode=0o700)
            os.chmod(root, 0o700)
            os.chmod(directory, 0o700)
            selected = SelectedTunnel("te_1", TUNNEL, ACCOUNT, "gen_2",
                                      "sink_1", "vault_ref_5", os.getuid(), True)
            with self.assertRaises(RemoteOriginDenied):
                write_provisioned_tunnel_token(selected, tunnel_token(),
                    verified_setup(tunnel_token(), account="00000000000000000000000000000000"),
                    token_root=root, journal=_Journal(), signer=HMACReceiptSigner(b"s" * 32),
                    now=lambda: 110.0)
            with self.assertRaises(RemoteOriginDenied):
                wrong_token = tunnel_token(tunnel="d1744f8b-faa1-48a4-9e5c-02ac921467fa")
                write_provisioned_tunnel_token(selected, wrong_token,
                    verified_setup(wrong_token, tunnel="d1744f8b-faa1-48a4-9e5c-02ac921467fa"),
                    token_root=root, journal=_Journal(), signer=HMACReceiptSigner(b"s" * 32),
                    now=lambda: 110.0)
            token = tunnel_token()
            receipt = write_provisioned_tunnel_token(selected, token, verified_setup(token),
                token_root=root, journal=_Journal(), signer=HMACReceiptSigner(b"s" * 32),
                now=lambda: 110.0)
            self.assertEqual(receipt.tunnel_id, TUNNEL)
            self.assertNotIn(token.decode(), repr(receipt))

    def test_custody_process_manager_joins_gateway_and_native_enrollments(self):
        selected = SelectedRemoteOrigin("remote_1", "gw_gen", "desktop_gen", "target_1",
            "a" * 64, "policy_rev", "b" * 64, "desktop.example.test",
            "https://desktop.example.test", True, "gateway", "gateway-enrollment",
            "c" * 64, "native", "native-enrollment")
        production_adapter = CustodyRemoteOriginProcessManager(_CustodyFixture())
        evidence = production_adapter.inspect_selected_origin(selected)
        self.assertEqual(evidence.gateway_generation, "gw_gen")
        self.assertEqual(evidence.desktop_generation, "desktop_gen")
        self.assertTrue(evidence.gateway_identity_digest)


if __name__ == "__main__":
    unittest.main()
