from __future__ import annotations

import asyncio
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
    OriginProbeObservation,
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

    def _request(self):
        value = {
            "schema": 1, "operation": "probe_selected_origin",
            "probe_handle": "h" * 43, "sequence": 1, "challenge": "c" * 43,
            "remote_enrollment_id": self.binding.remote_enrollment_id,
            "gateway_profile_id": self.binding.gateway_profile_id,
            "gateway_generation": self.binding.gateway_generation,
            "native_profile_id": self.binding.native_profile_id,
            "desktop_generation": self.binding.desktop_generation,
            "connector_target_id": self.binding.connector_target_id,
            "policy_config_digest": self.binding.policy_config_digest,
            "policy_revision": self.binding.policy_revision,
            "service_generation_digest": self.binding.service_generation_digest,
        }
        value["request_digest"] = hashlib.sha256(_canonical_json(value)).hexdigest()
        return value

    def test_exact_digest_and_selected_profile_pins_are_required(self):
        request = self._request()
        self.assertEqual(_valid_probe_request(request, self.binding), request)
        changed = dict(request, native_profile_id="other-profile")
        digest_input = {key: value for key, value in changed.items() if key != "request_digest"}
        changed["request_digest"] = hashlib.sha256(_canonical_json(digest_input)).hexdigest()
        with self.assertRaises(PrivateOriginProbeDenied):
            _valid_probe_request(changed, self.binding)

    def test_caller_cannot_select_routes_or_add_observation_claims(self):
        changed = self._request()
        changed["path"] = "/admin"
        with self.assertRaises(PrivateOriginProbeDenied):
            _valid_probe_request(changed, self.binding)

    def test_incomplete_or_false_runtime_observation_never_becomes_ready_response(self):
        complete = {
            "loopback_only": True,
            "unauthenticated_denied": True,
            "authorized_asset_served": True,
            "authorized_websocket_attached": True,
            "official_desktop_window_observed": True,
            "arbitrary_route_denied": True,
            "shell_route_denied": True,
            "full_host_desktop_denied": True,
        }
        with self.assertRaises(PrivateOriginProbeDenied):
            OriginProbeObservation({**complete, "shell_route_denied": False},
                                   ("probe:fixture",), "a" * 64,
                                   "ws-fixture", "window-fixture")
        with self.assertRaises(PrivateOriginProbeDenied):
            OriginProbeObservation({key: value for key, value in complete.items()
                                    if key != "official_desktop_window_observed"},
                                   ("probe:fixture",), "a" * 64,
                                   "ws-fixture", "window-fixture")

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
    async def run_selected_probe(self, binding, request):
        # This is a protocol fixture only; it does not establish Pi/Desktop
        # acceptance or production origin readiness.
        return OriginProbeObservation(
            assertions={
                "loopback_only": True,
                "unauthenticated_denied": True,
                "authorized_asset_served": True,
                "authorized_websocket_attached": True,
                "official_desktop_window_observed": True,
                "arbitrary_route_denied": True,
                "shell_route_denied": True,
                "full_host_desktop_denied": True,
            },
            assertion_ids=("fixture:http-deny", "fixture:asset", "fixture:ws", "fixture:window"),
            asset_sha256="a" * 64,
            websocket_observation_id="fixture-ws-1",
            native_window_observation_id="fixture-window-1",
        )


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

    def _request(self):
        value = {
            "schema": 1, "operation": "probe_selected_origin",
            "probe_handle": "h" * 43, "sequence": 1, "challenge": "c" * 43,
            "remote_enrollment_id": self.binding.remote_enrollment_id,
            "gateway_profile_id": self.binding.gateway_profile_id,
            "gateway_generation": self.binding.gateway_generation,
            "native_profile_id": self.binding.native_profile_id,
            "desktop_generation": self.binding.desktop_generation,
            "connector_target_id": self.binding.connector_target_id,
            "policy_config_digest": self.binding.policy_config_digest,
            "policy_revision": self.binding.policy_revision,
            "service_generation_digest": self.binding.service_generation_digest,
        }
        value["request_digest"] = hashlib.sha256(_canonical_json(value)).hexdigest()
        return value

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

    async def test_root_peer_gets_bound_probe_observation_and_replay_is_denied(self):
        server = await create_private_origin_probe_server(
            self.listener, self.binding,
            listener_identity=self._listener_identity(),
            peer_authorizer=lambda uid, gid, pid, pidfd, selected: (
                uid == os.getuid() and pid == os.getpid() and pidfd >= 0 and selected == self.binding),
            executor=_ObservedProbe(),
        )
        async with server:
            first = await self._roundtrip(self._request())
            self.assertEqual(first["challenge"], "c" * 43)
            self.assertEqual(first["request_digest"], self._request()["request_digest"])
            self.assertEqual(first["operation"], "probe_selected_origin_result")
            self.assertEqual(first["connector_target_id"], "xpra-native")
            self.assertEqual(set(first["observations"]), {
                "loopback_only", "unauthenticated_denied", "authorized_asset_served",
                "authorized_websocket_attached", "official_desktop_window_observed",
                "arbitrary_route_denied", "shell_route_denied", "full_host_desktop_denied",
            })
            replay = await self._roundtrip(self._request())
            self.assertEqual(replay, {"schema": 1, "error": "origin_probe_denied"})

    async def test_peer_denial_and_wrong_pin_never_run_probe(self):
        class NeverRun(PrivateOriginProbeExecutor):
            async def run_selected_probe(self, binding, request):
                raise AssertionError("denied request reached probe executor")

        server = await create_private_origin_probe_server(
            self.listener, self.binding,
            listener_identity=self._listener_identity(),
            peer_authorizer=lambda *_args: False,
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
            peer_authorizer=lambda uid, gid, pid, pidfd, selected: pidfd >= 0,
            executor=NeverRun(),
        )
        wrong_pin = self._request()
        wrong_pin["desktop_generation"] = "other-generation"
        digest_input = {key: value for key, value in wrong_pin.items() if key != "request_digest"}
        wrong_pin["request_digest"] = hashlib.sha256(_canonical_json(digest_input)).hexdigest()
        async with server:
            denied = await self._roundtrip(wrong_pin)
            self.assertEqual(denied, {"schema": 1, "error": "origin_probe_denied"})
