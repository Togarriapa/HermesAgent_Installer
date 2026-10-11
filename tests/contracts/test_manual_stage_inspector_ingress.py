"""Focused contract tests for the independent current Cloudflared ingress proof."""
from dataclasses import replace
from pathlib import Path
import hashlib
import json
import os
import socket
import struct
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from hermes_installer.remote import manual_stage_inspector as inspector


def _config():
    return SimpleNamespace(
        gateway_uid=996, gateway_gid=981, boot_id="12345678-1234-1234-1234-123456789abc",
        config_sha256="a" * 64, tunnel_unit_sha256="b" * 64,
        gateway_unit_sha256="c" * 64, cloudflared_binary_sha256="d" * 64,
        ingress_socket=inspector.INGRESS_SOCKET_PATH,
    )


def _proof_body(config, *, now, pid=321, uid=63324, gid=63324):
    body = {
        "schema": 1, "nonce": "f" * 64, "boot_id": config.boot_id,
        "issued_monotonic": now, "expires_monotonic": now + 5.0,
        "peer_pid": pid, "peer_uid": uid, "peer_gid": gid,
        "peer_start_ticks": "918273", "tunnel_unit_sha256": config.tunnel_unit_sha256,
        "tunnel_config_sha256": inspector._tunnel_config_digest(config),
        "tunnel_executable_sha256": config.cloudflared_binary_sha256,
        "origin_socket_device": 2049, "origin_socket_inode": 98765,
        "config_sha256": config.config_sha256,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    body["proof_sha256"] = hashlib.sha256(
        b"hermes-jarvis-mvp-ingress-observation-v263\0" + canonical).hexdigest()
    return body


class ManualStageInspectorIngressTests(unittest.TestCase):
    def test_valid_typed_proof_is_exact_peer_bound_and_expires_within_five_seconds(self):
        config = _config()
        issued = time.monotonic() - 0.05
        body = _proof_body(config, now=issued)
        proof = inspector.StageVerifiedIngressObservation(**body, _seal=inspector._OBSERVATION_SEAL)
        self.assertTrue(proof.verify_current(config, 321, 63324, 63324))
        self.assertLessEqual(proof.expires_monotonic - proof.issued_monotonic, 5.0)
        self.assertFalse(proof.verify_current(config, 321, 63325, 63324))
        self.assertFalse(proof.verify_current(config, 322, 63324, 63324))
        changed_config = SimpleNamespace(**{**vars(config), "config_sha256": "e" * 64})
        self.assertFalse(proof.verify_current(changed_config, 321, 63324, 63324))
        self.assertFalse(proof.verify_current(config, 321, 63324, 63324,
                                              now=proof.expires_monotonic))
        self.assertFalse(replace(proof, _seal=object()).verify_current(config, 321, 63324, 63324))

    def test_inspector_binds_peer_tuple_to_kernel_process_check_and_returns_canonical_proof(self):
        config = _config()
        peer = (321, 63324, 63324)
        gateway = (11, config.gateway_uid, config.gateway_gid, "1122", "gateway-inv", "1" * 64)
        tunnel = (12, peer[1], peer[2], "918273", "tunnel-inv", "2" * 64)
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
             mock.patch.object(inspector.os, "geteuid", return_value=0), \
             mock.patch.object(Path, "read_text", return_value=config.boot_id), \
             mock.patch.object(inspector, "_verify_origin_socket", return_value=(2049, 98765)), \
             mock.patch.object(inspector, "_fixed_process", side_effect=[gateway, tunnel]) as process, \
             mock.patch.object(inspector, "_pid_start_ticks", side_effect=["1122", "918273"]), \
             mock.patch.object(inspector, "_pidfd_exited", return_value=False), \
             mock.patch.object(inspector.os, "close"):
            result = inspector.observe_current_ingress(config, nonce="f" * 64,
                caller_pid=123, caller_uid=config.gateway_uid, caller_gid=config.gateway_gid,
                peer_pid=peer[0], peer_uid=peer[1], peer_gid=peer[2])
        self.assertEqual(result["peer_pid"], peer[0])
        self.assertEqual(result["peer_uid"], peer[1])
        self.assertEqual(result["peer_gid"], peer[2])
        self.assertEqual(result["peer_start_ticks"], tunnel[3])
        self.assertEqual(set(result), {
            "schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
            "peer_pid", "peer_uid", "peer_gid", "peer_start_ticks", "tunnel_unit_sha256",
            "tunnel_config_sha256", "tunnel_executable_sha256", "origin_socket_device",
            "origin_socket_inode", "config_sha256", "proof_sha256"})
        body = {key: value for key, value in result.items() if key != "proof_sha256"}
        expected = hashlib.sha256(b"hermes-jarvis-mvp-ingress-observation-v263\0" +
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        self.assertEqual(result["proof_sha256"], expected)
        self.assertEqual(process.call_count, 2)
        self.assertEqual(process.call_args_list[1].kwargs["expected_pid"], peer[0])
        self.assertEqual(process.call_args_list[1].kwargs["expected_uid"], peer[1])
        self.assertEqual(process.call_args_list[1].kwargs["expected_gid"], peer[2])

    def test_client_verifies_exact_response_fields_nonce_and_canonical_digest(self):
        config = _config()

        def exchange(response):
            response_raw = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("ascii")
            wire = struct.pack("!I", len(response_raw)) + response_raw

            class FakeSocket:
                def __init__(self, *_args):
                    self.remaining = wire
                def settimeout(self, _timeout):
                    pass
                def connect(self, _path):
                    pass
                def getsockopt(self, *_args):
                    return struct.pack("3i", 123, 0, 0)
                def sendall(self, _data):
                    pass
                def recv(self, count):
                    chunk, self.remaining = self.remaining[:count], self.remaining[count:]
                    return chunk
                def close(self):
                    pass

            class SocketStat:
                st_mode = __import__("stat").S_IFSOCK | 0o660
                st_uid = 0
                st_gid = config.gateway_gid

            with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                 mock.patch.object(inspector.os, "lstat", return_value=SocketStat()), \
                 mock.patch.object(inspector.os, "urandom", return_value=b"\xff" * 32), \
                 mock.patch.object(inspector.socket, "SO_PEERCRED", 17, create=True), \
                 mock.patch.object(inspector.socket, "socket", FakeSocket), \
                 mock.patch.object(Path, "read_text", return_value=config.boot_id):
                return inspector.verify_current_ingress(config, peer_pid=321,
                    peer_uid=63324, peer_gid=63324)

        body = _proof_body(config, now=time.monotonic() - 0.01)
        proof = exchange(body)
        self.assertTrue(proof.verify_current(config, 321, 63324, 63324))
        altered = dict(body)
        altered["peer_uid"] += 1
        with self.assertRaises(inspector.StageInspectionDenied):
            exchange(altered)
        altered = dict(body)
        altered["proof_sha256"] = "0" * 64
        with self.assertRaises(inspector.StageInspectionDenied):
            exchange(altered)

    def test_wrong_gateway_kernel_identity_and_wrong_socket_path_deny(self):
        config = _config()
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
             mock.patch.object(inspector.os, "geteuid", return_value=0):
            with self.assertRaises(inspector.StageInspectionDenied):
                inspector.observe_current_ingress(config, nonce="f" * 64,
                    caller_pid=123, caller_uid=config.gateway_uid + 1, caller_gid=config.gateway_gid,
                    peer_pid=321, peer_uid=63324, peer_gid=63324)
            with self.assertRaises(inspector.StageInspectionDenied):
                inspector.observe_current_ingress(SimpleNamespace(**{**vars(config),
                    "ingress_socket": Path("/tmp/origin.sock")}),
                    nonce="f" * 64, caller_pid=123, caller_uid=config.gateway_uid,
                    caller_gid=config.gateway_gid, peer_pid=321, peer_uid=63324, peer_gid=63324)

    def test_dynamic_tunnel_uid_gid_are_compared_to_live_proc_credentials(self):
        config = _config()
        props = {
            "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
            "MainPID": "321", "ControlGroup": "/system.slice/hermes-jarvis-mvp-tunnel.service",
            "FragmentPath": str(inspector.TUNNEL_UNIT_PATH), "DynamicUser": "yes",
            "SupplementaryGroups": "981", "DropInPaths": "", "InvocationID": "invocation",
        }
        good_proc = (99, 63324, 63324, "918273", inspector.TUNNEL_ARGV)
        common = (
            mock.patch.object(inspector, "_unit_props", return_value=props),
            mock.patch.object(inspector, "_hash_path", side_effect=[config.tunnel_unit_sha256,
                                                                       config.cloudflared_binary_sha256]),
            mock.patch.object(inspector, "_proc_identity", return_value=good_proc),
            mock.patch.object(Path, "read_text", return_value="0::/system.slice/hermes-jarvis-mvp-tunnel.service\n"),
            mock.patch.object(Path, "resolve", return_value=inspector.CLOUDFLARED_PATH),
            mock.patch.object(inspector, "_pid_start_ticks", return_value="918273"),
            mock.patch.object(inspector, "_pidfd_exited", return_value=False),
        )
        for patcher in common:
            patcher.start()
        try:
            checked = inspector._fixed_process(config, unit=inspector.TUNNEL_UNIT,
                expected_pid=321, expected_uid=63324, expected_gid=63324,
                executable=inspector.CLOUDFLARED_PATH,
                executable_sha256=config.cloudflared_binary_sha256,
                argv_expected=inspector.TUNNEL_ARGV, deadline=time.monotonic() + 2,
                supplementary_gid=config.gateway_gid, dynamic_user=True)
            self.assertEqual(checked[1:4], (63324, 63324, "918273"))
        finally:
            for patcher in reversed(common):
                patcher.stop()
        bad_proc = (99, 63325, 63324, "918273", inspector.TUNNEL_ARGV)
        with mock.patch.object(inspector, "_unit_props", return_value=props), \
             mock.patch.object(inspector, "_hash_path", side_effect=[config.tunnel_unit_sha256,
                                                                        config.cloudflared_binary_sha256]), \
             mock.patch.object(inspector, "_proc_identity", return_value=bad_proc), \
             mock.patch.object(Path, "read_text", return_value="0::/system.slice/hermes-jarvis-mvp-tunnel.service\n"), \
             mock.patch.object(Path, "resolve", return_value=inspector.CLOUDFLARED_PATH), \
             mock.patch.object(inspector, "_pid_start_ticks", return_value="918273"), \
             mock.patch.object(inspector.os, "close"), \
             mock.patch.object(inspector, "_pidfd_exited", return_value=False):
            with self.assertRaises(inspector.StageInspectionDenied):
                inspector._fixed_process(config, unit=inspector.TUNNEL_UNIT,
                    expected_pid=321, expected_uid=63324, expected_gid=63324,
                    executable=inspector.CLOUDFLARED_PATH,
                    executable_sha256=config.cloudflared_binary_sha256,
                    argv_expected=inspector.TUNNEL_ARGV, deadline=time.monotonic() + 2,
                    supplementary_gid=config.gateway_gid, dynamic_user=True)

    def test_unit_templates_grant_only_expected_runtime_directory_and_tunnel_group(self):
        repo = Path(__file__).resolve().parents[2]
        gateway = (repo / "templates/manual-stage/hermes-jarvis-mvp-gateway.service").read_text()
        tunnel = (repo / "templates/manual-stage/hermes-jarvis-mvp-tunnel.service").read_text()
        self.assertIn("RuntimeDirectory=hermes-jarvis-mvp-gateway", gateway)
        self.assertIn("RuntimeDirectoryMode=0750", gateway)
        self.assertEqual(tunnel.count("SupplementaryGroups=981"), 1)
        self.assertIn("DynamicUser=yes", tunnel)

    def test_fixed_unit_readback_rejects_any_drop_in_override(self):
        props = ("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=321\n"
                 "ControlGroup=/system.slice/hermes-jarvis-mvp-tunnel.service\n"
                 "FragmentPath=/etc/systemd/system/hermes-jarvis-mvp-tunnel.service\n"
                 "DynamicUser=yes\nSupplementaryGroups=981\nDropInPaths=\nInvocationID=invocation\n")
        with mock.patch.object(inspector, "_run_fixed", return_value=props.encode("ascii")):
            self.assertEqual(inspector._unit_props(inspector.TUNNEL_UNIT,
                deadline=time.monotonic() + 2)["DropInPaths"], "")
        overridden = props.replace("DropInPaths=\n", "DropInPaths=/run/systemd/system/tunnel.service.d/override.conf\n")
        with mock.patch.object(inspector, "_run_fixed", return_value=overridden.encode("ascii")):
            with self.assertRaises(inspector.StageInspectionDenied):
                inspector._unit_props(inspector.TUNNEL_UNIT, deadline=time.monotonic() + 2)

    @unittest.skipUnless(inspector.GATEWAY_EXECUTABLE.exists(),
                         "fixed Pi Python executable is absent on this host")
    def test_gateway_executable_is_accepted_by_actual_root_readonly_hash_path(self):
        digest = inspector._hash_path(inspector.GATEWAY_EXECUTABLE, require_root_readonly=True)
        self.assertEqual(digest, inspector.GATEWAY_EXECUTABLE_SHA256)


if __name__ == "__main__":
    unittest.main()
