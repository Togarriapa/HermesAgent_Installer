from __future__ import annotations

import hashlib
import os
import socket
import struct
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from hermes_installer.authority.remote_observations import (
    GatewayBoundaryHTTPFact,
    GatewayBoundaryObservation,
    NativeWindowInputObservation,
    NativeWindowObservation,
    RemoteObservationUnavailable,
    SelectedGatewayBoundary,
    SelectedNativeWindow,
    _loopback_http,
    _owner_pid,
    _read_xauthority,
    _require_root_linux,
    _verify_ledger_capability,
)
from hermes_installer.authority.remote_origin import HMACReceiptSigner


class RemoteObservationContracts(unittest.TestCase):
    def setUp(self):
        self.signer = HMACReceiptSigner(b"r" * 32)
        self.selected = SelectedGatewayBoundary(
            remote_enrollment_id="remote-1", gateway_profile_id="gateway-profile",
            gateway_generation="g7", gateway_identity_digest="a" * 64,
            hostname="desktop.example.test", listener_port=18765,
            policy_config_digest="b" * 64, policy_revision="policy-3")

    def test_gateway_receipt_signature_binds_policy_listener_and_all_denials(self):
        requests = {
            key: GatewayBoundaryHTTPFact(
                403 if key == "unauthenticated" else 404, 0,
                hashlib.sha256(key.encode()).hexdigest(),
                hashlib.sha256((key + " response").encode()).hexdigest())
            for key in ("unauthenticated", "arbitrary-route", "shell-route", "full-host-desktop")
        }
        unsigned = GatewayBoundaryObservation(
            gateway_identity_digest=self.selected.gateway_identity_digest,
            policy_config_digest=self.selected.policy_config_digest,
            policy_revision=self.selected.policy_revision,
            network_namespace_inode=77,
            listener_addresses=("127.0.0.1:18765",), requests=requests,
            issued_monotonic=100.0, expires_monotonic=110.0,
            assertion_ids=(
                "remote-boundary:loopback-listener",
                "remote-boundary:unauthenticated-before-connector",
                "remote-boundary:arbitrary-route-before-connector",
                "remote-boundary:shell-route-before-connector",
                "remote-boundary:full-host-desktop-before-connector",
            ), signature=b"")
        receipt = GatewayBoundaryObservation(**{
            field: getattr(unsigned, field) for field in unsigned.__dataclass_fields__ if field != "signature"
        }, signature=self.signer.sign(unsigned.payload()))
        self.assertTrue(receipt.verify(self.signer, now=105.0, selected=self.selected))
        changed_policy = SelectedGatewayBoundary(**{
            field: getattr(self.selected, field) for field in self.selected.__dataclass_fields__
            if field != "policy_config_digest"
        }, policy_config_digest="c" * 64)
        self.assertFalse(receipt.verify(self.signer, now=105.0, selected=changed_policy))
        self.assertFalse(receipt.verify(self.signer, now=111.0, selected=self.selected))

    def test_actual_bounded_loopback_exchange_hashes_wire_bytes(self):
        observed = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(inner_self):
                observed["path"] = inner_self.path
                observed["authorization"] = inner_self.headers.get("Authorization")
                inner_self.send_response(404)
                inner_self.end_headers()
                inner_self.wfile.write(b"not found")

            def log_message(inner_self, *_args):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = b"GET /api/backend HTTP/1.1\r\nHost: desktop.example.test\r\nConnection: close\r\n\r\n"
            response, wire = _loopback_http(server.server_port, request, 1.0)
            self.assertEqual(response.status, 404)
            self.assertEqual(response.body, b"not found")
            self.assertEqual(observed, {"path": "/api/backend", "authorization": None})
            self.assertIn(b"HTTP/1.0 404", wire)
            self.assertIn(b"not found", wire)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_xres_resource_base_maps_server_client_pid_not_window_label(self):
        self.assertEqual(_owner_pid(0x200041, ((0x200000, 0x1FFFFF, 442),)), 442)
        self.assertIsNone(_owner_pid(0x400041, ((0x200000, 0x1FFFFF, 442),)))
        with self.assertRaises(RemoteObservationUnavailable):
            _owner_pid(0x200041, ((0x200000, 0x1FFFFF, 442), (0x200000, 0x0FFFFF, 443)))

    def test_native_receipt_binds_selected_profile_and_consumed_stream(self):
        selected = SelectedNativeWindow(
            remote_enrollment_id="remote-1", native_profile_id="desktop-profile",
            native_generation="native-4", native_uid=1000, native_cgroup_id="cg-1",
            allowed_executable_sha256s=("a" * 64,),
            display_server_profile_id="xpra-profile", display_server_generation="x1",
            display_name=":100", xauthority_path=Path("/private/authority"),
            xauthority_device=1, xauthority_inode=2, xauthority_uid=0)
        assertions = (
            "remote-window:xres-local-client-pid", "remote-window:pidfd-live",
            "remote-window:profile-cgroup", "remote-window:official-package-executable",
            "remote-window:selected-xserver-peer", "remote-window:active-viewable-window",
            "remote-window:bound-websocket-observation")
        unsigned = NativeWindowObservation(
            profile_id="desktop-profile", generation="native-4", uid=1000,
            pid=442, pid_starttime_ticks=991,
            websocket_observation_id="w" * 24,
            window_identity_sha256="b" * 64, surface_sha256="c" * 64,
            issued_monotonic=100.0, expires_monotonic=110.0,
            assertion_ids=assertions, signature=b"")
        receipt = NativeWindowObservation(**{
            field: getattr(unsigned, field) for field in unsigned.__dataclass_fields__
            if field != "signature"
        }, signature=self.signer.sign(unsigned.payload()))
        self.assertTrue(receipt.verify(self.signer, now=105.0, selected=selected,
                                       websocket_observation_id="w" * 24))
        self.assertFalse(receipt.verify(self.signer, now=105.0, selected=selected,
                                        websocket_observation_id="x" * 24))

    def test_input_receipt_distinguishes_complete_and_partial_measured_delivery(self):
        selected = SelectedNativeWindow(
            remote_enrollment_id="remote-1", native_profile_id="desktop-profile",
            native_generation="native-4", native_uid=1000, native_cgroup_id="cg-1",
            allowed_executable_sha256s=("a" * 64,),
            display_server_profile_id="xpra-profile", display_server_generation="x1",
            display_name=":100", xauthority_path=Path("/private/authority"),
            xauthority_device=1, xauthority_inode=2, xauthority_uid=0,
            xauthority_receipt_handle="receipt_handle_1234567890")
        assertions = (
            "remote_desktop.native_input.current_selected_xres_window",
            "remote_desktop.native_input.focus_observed_at_each_f24_boundary",
            "remote_desktop.native_input.f24_event_delivery_measured",
            "remote_desktop.native_input.focus_restore_observed_and_identity_revalidated")

        def signed(*, outcome, press, release, focus_stable):
            unsigned = NativeWindowInputObservation(
                remote_enrollment_id="remote-1", websocket_observation_id="w" * 24,
                native_profile_id="desktop-profile", native_generation="native-4",
                native_pid=442, native_pid_start_ticks=991,
                display_profile_id="xpra-profile", display_generation="x1",
                display_name=":100", xauthority_receipt_handle="receipt_handle_1234567890",
                window_id=0x200041, keycode=194,
                delivered_keypress_count=press, delivered_keyrelease_count=release,
                delivered_event_types=((2, 3) if press == 1 and release == 1 else (2,)),
                focus_stable=focus_stable, focus_restored=focus_stable, outcome=outcome,
                focus_observation_handle="f" * 64, event_observation_handle="e" * 64,
                issued_monotonic=100.0, expires_monotonic=105.0,
                assertion_ids=assertions, signature=b"")
            return NativeWindowInputObservation(**{
                name: getattr(unsigned, name)
                for name in unsigned.__dataclass_fields__ if name != "signature"
            }, signature=self.signer.sign(unsigned.payload()))

        complete = signed(outcome="complete", press=1, release=1, focus_stable=True)
        partial = signed(outcome="partial", press=1, release=0, focus_stable=False)
        self.assertTrue(complete.verify(self.signer, now=101.0, selected=selected,
                                        websocket_observation_id="w" * 24))
        self.assertTrue(partial.verify(self.signer, now=101.0, selected=selected,
                                       websocket_observation_id="w" * 24))
        self.assertFalse(NativeWindowInputObservation(**{
            name: getattr(partial, name)
            for name in partial.__dataclass_fields__ if name != "outcome"
        }, outcome="complete").verify(self.signer, now=101.0, selected=selected,
                                       websocket_observation_id="w" * 24))

    def test_ledger_capability_is_selected_and_short_lived(self):
        from types import SimpleNamespace

        capability = SimpleNamespace(
            probe_handle="p" * 43, remote_enrollment_id="remote-1",
            gateway_identity_digest=self.selected.gateway_identity_digest,
            gateway_profile_id="gateway-profile", gateway_generation="g7",
            native_enrollment_id="native-enrollment", session_id="session",
            policy_config_digest=self.selected.policy_config_digest,
            policy_revision=self.selected.policy_revision, issued_monotonic=100.0,
            expires_monotonic=104.0, signature=b"root-signature")
        _verify_ledger_capability(capability, enrollment_id="remote-1",
            gateway_identity_digest=self.selected.gateway_identity_digest,
            deadline=105.0, now=101.0)
        with self.assertRaises(RemoteObservationUnavailable):
            _verify_ledger_capability(capability, enrollment_id="remote-other",
                gateway_identity_digest=self.selected.gateway_identity_digest,
                deadline=105.0, now=101.0)
        with self.assertRaises(RemoteObservationUnavailable):
            _verify_ledger_capability(capability, enrollment_id="remote-1",
                gateway_identity_digest=self.selected.gateway_identity_digest,
                deadline=105.0, now=104.0)

    def test_xauthority_reader_selects_one_local_cookie_and_keeps_path_private(self):
        hostname = socket.gethostname().encode("ascii", "ignore")
        cookie = b"0123456789abcdef"

        def field(value: bytes) -> bytes:
            return struct.pack(">H", len(value)) + value

        record = struct.pack(">H", 256) + field(hostname) + field(b"100") + field(
            b"MIT-MAGIC-COOKIE-1") + field(cookie)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority"
            path.write_bytes(record)
            path.chmod(0o600)
            stat_result = path.stat()
            row = SelectedNativeWindow(
                remote_enrollment_id="remote-1", native_profile_id="desktop-profile",
                native_generation="native-4", native_uid=1000, native_cgroup_id="cg-1",
                allowed_executable_sha256s=("a" * 64,),
                display_server_profile_id="xpra-profile", display_server_generation="x1",
                display_name=":100", xauthority_path=path,
                xauthority_device=stat_result.st_dev, xauthority_inode=stat_result.st_ino,
                xauthority_uid=stat_result.st_uid)
            self.assertEqual(bytes(_read_xauthority(row, "100")), cookie)
            path.write_bytes(record + record)
            path.chmod(0o600)
            refreshed = path.stat()
            duplicate = SelectedNativeWindow(**{
                field_name: getattr(row, field_name)
                for field_name in row.__dataclass_fields__ if field_name not in {
                    "xauthority_device", "xauthority_inode"}
            }, xauthority_device=refreshed.st_dev, xauthority_inode=refreshed.st_ino)
            with self.assertRaises(RemoteObservationUnavailable):
                _read_xauthority(duplicate, "100")

    @unittest.skipIf(os.name == "posix" and Path("/proc/self/stat").exists(),
                     "Linux root observer is present on this host")
    def test_non_linux_host_cannot_claim_root_process_observations(self):
        with self.assertRaises(RemoteObservationUnavailable):
            _require_root_linux()


if __name__ == "__main__":
    unittest.main()
