from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.server import (
    OriginProbeActionResult,
    ProbeActionAuthorization,
    PrivateOriginProbeExecutor,
    PrivateOriginProbeDenied,
    SelectedOriginProbeBinding,
    SelectedOriginProbeListener,
    _valid_probe_request,
    _canonical_json,
    create_private_origin_probe_server,
)


class PrivateOriginProbeRequestTests(unittest.TestCase):
    def setUp(self):
        self.binding = SelectedOriginProbeBinding(
            remote_enrollment_id="remote-enrollment", gateway_profile_id="gateway-profile",
            gateway_generation="gateway-gen", native_profile_id="native-profile",
            desktop_generation="desktop-gen", connector_target_id="xpra-native",
            policy_config_digest="b" * 64, policy_revision="policy-r1",
            service_generation_digest="c" * 64,
        )

    def _request(self, action="asset-get"):
        return {"schema": 1, "probe_handle": "h" * 43,
                "action": action,
                "asset_id": "a" * 64 if action != "websocket-attach" else None}

    def test_only_fixed_child_actions_and_opaque_asset_ids_are_accepted(self):
        request = self._request()
        self.assertEqual(_valid_probe_request(request, self.binding), request)
        with self.assertRaises(PrivateOriginProbeDenied):
            _valid_probe_request(dict(request, action="full-host-desktop"), self.binding)
        with self.assertRaises(PrivateOriginProbeDenied):
            _valid_probe_request(dict(request, asset_id="../admin"), self.binding)

    def test_caller_cannot_select_routes_or_add_observation_claims(self):
        changed = self._request()
        changed["url"] = "http://127.0.0.1/admin"
        with self.assertRaises(PrivateOriginProbeDenied):
            _valid_probe_request(changed, self.binding)

    def test_malformed_action_bytes_never_become_probe_response(self):
        with self.assertRaises(PrivateOriginProbeDenied):
            OriginProbeActionResult("asset-get", "a" * 64,
                {"status_code": 200, "headers": {}, "body_b64": "", "body_sha256": "a" * 64})
        with self.assertRaises(PrivateOriginProbeDenied):
            OriginProbeActionResult("unknown", None, {})

    def test_probe_executor_is_not_a_placeholder_base_class(self):
        with self.assertRaises(TypeError):
            PrivateOriginProbeExecutor()

    @unittest.skipUnless(importlib.util.find_spec("aiohttp"), "aiohttp isolated runtime is unavailable")
    def test_probe_control_is_not_registered_as_a_public_http_route(self):
        from hermes_installer.remote.gateway import RemotePolicy
        from hermes_installer.remote.server import GatewayRuntime, create_app

        runtime = GatewayRuntime(RemotePolicy(
            "desk.example.net", "https://team.cloudflareaccess.com", "aud",
            frozenset({"owner@example.net"}), {}))
        app = create_app(runtime)
        public_paths = {route.resource.canonical for route in app.router.routes()
                        if hasattr(route.resource, "canonical")}
        self.assertFalse(any("probe" in path.casefold() for path in public_paths))
        self.assertIn("/session", public_paths)


class _ObservedProbe(PrivateOriginProbeExecutor):
    async def authorize_action(self, binding, request, *, peer_uid, peer_pid, peer_pidfd):
        if peer_pidfd < 0:
            raise PrivateOriginProbeDenied("missing fixture PIDFD")
        return ProbeActionAuthorization(
            request["probe_handle"], request["action"], request["asset_id"],
            binding.gateway_profile_id, binding.gateway_generation,
            binding.native_profile_id, binding.desktop_generation,
            binding.connector_target_id, binding.policy_config_digest,
            binding.policy_revision, binding.service_generation_digest, 9999999999.0)

    async def run_selected_action(self, binding, request, *, peer_uid, peer_pid, peer_pidfd):
        # Protocol fixture only: the private socket path is exercised, but this
        # adapter does not establish target or desktop readiness.
        if request["action"] == "websocket-attach":
            frame = b"fixture-binary"
            digest = hashlib.sha256(frame).hexdigest()
            return OriginProbeActionResult("websocket-attach", None, {
                "status_code": 101, "frame_b64": base64.b64encode(frame).decode(),
                "frame_bytes": len(frame), "frame_count": 1, "frame_sha256": digest,
                "observation_id": hashlib.sha256(b"hermes-probe-ws-v1\0" + frame).hexdigest()})
        body = b"fixture asset"
        if request["action"] == "asset-head":
            body = b""
        return OriginProbeActionResult(request["action"], request["asset_id"], {
            "status_code": 200, "headers": {}, "body_b64": base64.b64encode(body).decode(),
            "body_sha256": hashlib.sha256(body).hexdigest()})


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
                     and hasattr(socket, "SO_PEERCRED"), "requires Linux AF_UNIX peer credentials")
class PrivateOriginProbeControlTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.socket_path = str(Path(self.temp.name) / "origin-probe.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        self.listener.listen(4)
        self.binding = SelectedOriginProbeBinding(
            remote_enrollment_id="remote-enrollment", gateway_profile_id="gateway-profile",
            gateway_generation="gateway-gen",
            native_profile_id="native-profile",
            desktop_generation="desktop-gen", connector_target_id="xpra-native",
            policy_config_digest="b" * 64, policy_revision="policy-r1",
            service_generation_digest="c" * 64,
        )

    def _listener_identity(self):
        st = os.lstat(self.socket_path)
        return SelectedOriginProbeListener(self.socket_path, st.st_dev, st.st_ino, st.st_uid,
                                           "gateway-profile", self.binding.gateway_generation)

    def tearDown(self):
        self.listener.close()
        self.temp.cleanup()

    def _request(self, action="asset-get", handle="h" * 43):
        return {"schema": 1, "probe_handle": handle, "action": action,
                "asset_id": "a" * 64 if action != "websocket-attach" else None}

    async def _roundtrip(self, request):
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        frame = _canonical_json(request)
        writer.write(struct.pack("!I", len(frame)) + frame)
        await writer.drain()
        size = struct.unpack("!I", await asyncio.wait_for(reader.readexactly(4), timeout=2))[0]
        response = json.loads(await asyncio.wait_for(reader.readexactly(size), timeout=2))
        writer.close()
        await writer.wait_closed()
        return response

    async def test_root_peer_gets_action_bytes_and_child_handle_replay_is_denied(self):
        server = await create_private_origin_probe_server(
            self.listener, self.binding,
            listener_identity=self._listener_identity(),
            executor=_ObservedProbe(),
        )
        async with server:
            first = await self._roundtrip(self._request())
            self.assertEqual(first["operation"], "probe_action_result")
            self.assertEqual(first["action"], "asset-get")
            self.assertEqual(first["result"]["status_code"], 200)
            self.assertEqual(first["result"]["body_sha256"], hashlib.sha256(b"fixture asset").hexdigest())
            digest_body = {key: value for key, value in first.items() if key != "result_digest"}
            self.assertEqual(first["result_digest"], hashlib.sha256(_canonical_json(digest_body)).hexdigest())
            ws = await self._roundtrip(self._request(action="websocket-attach", handle="w" * 43))
            self.assertEqual(ws["result"]["status_code"], 101)
            self.assertEqual(ws["result"]["frame_count"], 1)
            self.assertEqual(ws["result"]["frame_sha256"], hashlib.sha256(b"fixture-binary").hexdigest())
            replay = await self._roundtrip(self._request())
            self.assertEqual(replay, {"schema": 1, "error": "origin_probe_denied"})

    async def test_peer_denial_and_wrong_pin_never_run_probe(self):
        class NeverRun(PrivateOriginProbeExecutor):
            async def authorize_action(self, binding, request, *, peer_uid, peer_pid, peer_pidfd):
                raise PrivateOriginProbeDenied("fixture peer denied")

            async def run_selected_action(self, binding, request, *, peer_uid, peer_pid, peer_pidfd):
                raise AssertionError("denied request reached probe executor")

        server = await create_private_origin_probe_server(
            self.listener, self.binding,
            listener_identity=self._listener_identity(),
            executor=NeverRun(),
        )
        async with server:
            denied = await self._roundtrip(self._request())
            self.assertEqual(denied, {"schema": 1, "error": "origin_probe_denied"})

        self.listener.close()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        self.listener.listen(4)
        server = await create_private_origin_probe_server(
            self.listener, self.binding,
            listener_identity=self._listener_identity(),
            executor=NeverRun(),
        )
        wrong_pin = {"schema": 1, "probe_handle": "i" * 43,
                     "action": "websocket-attach", "asset_id": "a" * 64}
        async with server:
            denied = await self._roundtrip(wrong_pin)
            self.assertEqual(denied, {"schema": 1, "error": "origin_probe_denied"})
