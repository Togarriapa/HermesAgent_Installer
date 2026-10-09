"""Real loopback effects and denials for the fixed HI07 connector fixture."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import unittest
from dataclasses import replace

from hermes_installer.authority.types import (
    AuthorityDenied, EffectAuthorization, HostContext, Sensitivity, canonical_digest,
)
from hermes_installer.service_connector import (
    FixedServiceConnector, ROUTES, Route, ServiceConnectorClient,
    open_request_bytes, _parse_http_frame,
)


def _context(operation: str, *, generation: str = "generation:1", payload: bytes | None = None) -> HostContext:
    return HostContext(
        principal_id="principal:fixture", profile_id="hermes-desktop",
        namespace_id="namespace:fixture", uid=1234, purpose="remote.desktop",
        intent_id="session:fixture", trace_id="trace:fixture", sensitivity=Sensitivity.PRIVATE,
        lineage_hash="a" * 64, policy_revision="policy:fixture",
        capabilities=frozenset({"hermes-service-connect"}), issued_at_monotonic=time.monotonic(),
        monotonic_expires_at=time.monotonic() + 30, nonce="nonce:fixture",
        grant_id="grant:context", signature="signature:fixture", enrollment_id="enrollment:fixture",
        generation=generation, operation=operation,
        final_payload_digest=canonical_digest(payload) if payload is not None else None,
    )


def _authorization(context: HostContext, operation: str, target: str, payload: bytes) -> EffectAuthorization:
    context_digest = canonical_digest({**context.claims(), "signature": context.signature})
    return EffectAuthorization(
        principal_id=context.principal_id, profile_id=context.profile_id,
        namespace_id=context.namespace_id, uid=context.uid, purpose=context.purpose,
        sensitivity=context.sensitivity, trace_id=context.trace_id,
        policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
        capability="hermes-service-connect", intent_id=context.intent_id, target=target,
        recipient=None, request_digest=canonical_digest(payload), retry_index=0,
        issued_at_monotonic=time.monotonic(), monotonic_expires_at=time.monotonic() + 10,
        grant_id=f"grant:{operation}", nonce=f"nonce:{operation}", context_digest=context_digest,
        signature="signature:grant", enrollment_id=context.enrollment_id,
        generation=context.generation, operation=operation,
        final_payload_digest=canonical_digest(payload),
    )


def _call(connector, operation, payload, *, target="xpra-native", pid=None, pidfd=None,
          cancelled=lambda: False):
    context = _context(operation, payload=payload)
    auth = _authorization(context, operation, target, payload)
    return getattr(connector, operation.rsplit(".", 1)[1])(
        context=context, authorization=auth, payload=payload, timeout=2.0,
        peer_pid=os.getpid() if pid is None else pid, peer_pidfd=pidfd,
        cancelled=cancelled,
    )


@unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(os, "setns"),
                     "HI07 kernel effect fixtures require Linux pidfds and namespaces")
class FixedServiceConnectorContracts(unittest.TestCase):
    def setUp(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.route_key = ("xpra-native", "xpra-http")
        self.original_route = ROUTES[self.route_key]
        ROUTES[self.route_key] = replace(self.original_route, port=self.port)
        self.accepted = threading.Event()
        self.received = bytearray()
        self.http_response_mode = False
        def echo():
            peer, _ = self.listener.accept()
            self.accepted.set()
            try:
                if self.http_response_mode:
                    while b"\r\n\r\n" not in self.received:
                        data = peer.recv(4096)
                        if not data:
                            break
                        self.received.extend(data)
                    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello")
                else:
                    while data := peer.recv(4096):
                        self.received.extend(data)
                        peer.sendall(data)
            finally:
                peer.close()
        self.echo_thread = threading.Thread(target=echo, daemon=True)
        self.echo_thread.start()
        self.resolve_calls = []
        self.pidfd = os.pidfd_open(os.getpid()) if hasattr(os, "pidfd_open") else -1
        class Lease:
            namespace_fd = -1
            pidfd = self.pidfd
            uid = 1234
            cgroup_identity = "fixture-cgroup"
            generation = "generation:1"
            process_id = "registered-process"
            def close(self):
                pass
        def resolve(*args):
            self.resolve_calls.append(args)
            return Lease()
        self.connector = FixedServiceConnector(
            resolve_service_namespace=resolve, _test_allow_current_namespace=True,
        )

    def tearDown(self):
        self.connector.shutdown()
        self.listener.close()
        ROUTES[self.route_key] = self.original_route
        if self.pidfd >= 0:
            os.close(self.pidfd)

    def _open(self):
        payload = open_request_bytes(
            enrollment_id="enrollment:fixture", generation="generation:1",
            target_id="xpra-native", route_id="xpra-http",
            session_id="session:fixture", deadline=time.monotonic() + 5,
        )
        result = _call(self.connector, "connector.open", payload, pidfd=self.pidfd)
        return json.loads(result["body"])

    def test_fixed_loopback_stream_performs_write_and_read_with_sequence(self):
        opened = self._open()
        self.assertTrue(self.accepted.wait(2))
        request = b"GET /client/index.html HTTP/1.1\r\nHost: attacker.invalid\r\nAccept: text/html\r\n\r\n"
        write = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http", "connector_id": opened["connector_id"],
                 "session_id": "session:fixture", "generation": "generation:1",
                 "deadline": time.monotonic() + 2, "sequence": 0,
                 "data_b64": __import__("base64").b64encode(request).decode("ascii")}
        _call(self.connector, "connector.write", json.dumps(write, sort_keys=True, separators=(",", ":")).encode(), pidfd=self.pidfd)
        read = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http", "connector_id": opened["connector_id"],
                "session_id": "session:fixture", "generation": "generation:1",
                "deadline": time.monotonic() + 2, "sequence": 1, "max_bytes": 1024}
        response = _call(self.connector, "connector.read", json.dumps(read, sort_keys=True, separators=(",", ":")).encode(), pidfd=self.pidfd)
        normalized = b"GET /client/index.html HTTP/1.1\r\nHost: 127.0.0.1:" + str(self.port).encode() + b"\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        self.assertEqual(__import__("base64").b64decode(json.loads(response["body"])["data_b64"]), normalized)
        self.assertEqual(bytes(self.received), normalized)
        self.assertEqual(self.resolve_calls, [("enrollment:fixture", "hermes-desktop", "generation:1", "xpra-native", "xpra-http")])

    def test_unknown_route_and_stale_generation_are_denied_before_resolution(self):
        payload = open_request_bytes(
            enrollment_id="enrollment:fixture", generation="generation:1",
            target_id="xpra-native", route_id="xpra-http", session_id="session:fixture",
            deadline=time.monotonic() + 5,
        )
        altered = payload.replace(b"xpra-http", b"evil-route")
        with self.assertRaises(AuthorityDenied):
            _call(self.connector, "connector.open", altered, pidfd=self.pidfd)
        stale_context = _context("connector.open", generation="generation:old", payload=payload)
        stale_auth = _authorization(stale_context, "connector.open", "xpra-native", payload)
        with self.assertRaises(AuthorityDenied):
            self.connector.open(context=stale_context, authorization=stale_auth, payload=payload,
                                timeout=2, peer_pid=os.getpid(), peer_pidfd=self.pidfd,
                                cancelled=lambda: False)
        self.assertEqual(self.resolve_calls, [])

    def test_foreign_pid_cannot_use_an_open_stream(self):
        opened = self._open()
        payload = json.dumps({"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                              "connector_id": opened["connector_id"], "session_id": "session:fixture",
                              "generation": "generation:1", "deadline": time.monotonic() + 2,
                              "sequence": 0, "max_bytes": 16}, sort_keys=True,
                             separators=(",", ":")).encode()
        with self.assertRaises(AuthorityDenied):
            _call(self.connector, "connector.read", payload, pid=os.getpid() + 1, pidfd=self.pidfd)

    def test_cancelled_read_closes_retained_stream_and_peer(self):
        opened = self._open()
        payload = json.dumps({"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                              "connector_id": opened["connector_id"], "session_id": "session:fixture",
                              "generation": "generation:1", "deadline": time.monotonic() + 2,
                              "sequence": 0, "max_bytes": 16}, sort_keys=True,
                             separators=(",", ":")).encode()
        with self.assertRaises(AuthorityDenied):
            _call(self.connector, "connector.read", payload, pidfd=self.pidfd, cancelled=lambda: True)
        self.assertNotIn(opened["connector_id"], self.connector._streams)

    def test_hi13_backend_drives_fixed_socket_effect_and_closes_it(self):
        from types import SimpleNamespace
        from hermes_installer.service_connector import RemoteServiceConnectorBackend
        from hermes_installer.authority.remote_connector_authority import (
            AuthorityServiceHI12Adapter, GatewayRoleProof, RemoteConnectorEffectAuthority,
        )
        from hermes_installer.authority.remote_sessions import (
            RemoteConnectorBinding, RemoteGatewayIdentity, RemoteRuntimeState,
        )
        from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
        from hermes_installer.authority.types import Sensitivity

        session_id = "session:fixture"
        lease_deadline = time.monotonic() + 20
        peer_uid, peer_pid, peer_pidfd = 1234, os.getpid(), self.pidfd
        gateway_identity = RemoteGatewayIdentity(
            peer_uid, peer_pid, "123456", "b" * 64, "gateway-cgroup", "gateway-profile",
            "gateway-generation", "c" * 64, gid=peer_uid, pid_starttime_ticks="123456",
            executable_device=2049, executable_inode=7001, mount_namespace_inode=3001,
            network_namespace_inode=3002, enrollment_id="enrollment:fixture",
            pidfd_registry_handle="registry:fixture",
        )
        binding = RemoteConnectorBinding(
            enrollment_id="enrollment:fixture", session_id=session_id,
            action="asset-read", route_id="xpra-http", target_id="xpra-native",
            subject="subject:fixture", principal_id="principal:remote",
            profile_id="user-profile", profile_generation="user-generation",
            gateway_profile_id="gateway-profile", gateway_generation="gateway-generation",
            native_profile_id="hermes-desktop", native_generation="generation:1",
            policy_revision="policy:fixture", policy_config_digest="d" * 64,
            service_generation_digest="e" * 64, connector_handle=None, next_sequence=0,
            gateway_identity=gateway_identity, token_fingerprint="f" * 64,
            issued_monotonic=time.monotonic(), lease_expires_monotonic=lease_deadline,
            frame_deadline_monotonic=lease_deadline, cancelled=lambda: False,
        )
        state = RemoteRuntimeState(
            "enrollment:fixture", "policy:fixture", "d" * 64, "gateway-generation",
            "generation:1", "hermes-desktop", "generation:1", "b" * 64,
            "xpra-native", "a" * 64, "e" * 64,
        )
        protected_remote = SimpleNamespace(
            enrollment_id="enrollment:fixture", gateway_profile_id="gateway-profile",
            gateway_generation="gateway-generation", gateway_role_artifact_id="gateway-role",
            gateway_role_sha256="b" * 64, native_desktop_profile_id="hermes-desktop",
            native_generation="generation:1", connector_target_id="xpra-native",
            policy_revision="policy:fixture", policy_config_digest="d" * 64,
        )
        entrypoint_artifact_id, entrypoint_digest = "gateway-entrypoint", "9" * 64
        role_proof = GatewayRoleProof(
            "enrollment:fixture", "gateway-profile", "gateway-generation", "b" * 64,
            "gateway-role", "b" * 64, entrypoint_artifact_id, entrypoint_digest,
            "boot:fixture", time.monotonic() - 1, time.monotonic() + 30,
        )

        class Policy:
            def classify(self, *, purpose, intent, source_contexts, binding):
                return Sensitivity.PRIVATE, "a" * 64
            def allow_effect(self, *, context, rule, request_digest, retry_index):
                return context.sensitivity is Sensitivity.PRIVATE and retry_index == 0

        operations = ("connector.open", "connector.read", "connector.write", "connector.close")
        effect_rules = {("hermes-service-connect", operation, "xpra-native"):
                        EffectRule("hermes-service-connect", operation, "xpra-native")
                        for operation in operations}
        effect_handlers = {(operation, "xpra-native"):
                           (lambda **_: {"status": 200, "body": b"", "headers": {}, "receipt_id": "fixture"})
                           for operation in operations}
        service = AuthorityService(
            signing_key=b"k" * 32, key_id="fixture-authority",
            bindings_by_uid={2001: PrincipalBinding(
                2001, "principal:native", "hermes-desktop", "namespace:native",
                frozenset({"hermes-service-connect"}))},
            rules=effect_rules, handlers=effect_handlers, policy=Policy(),
            profile_generations={"hermes-desktop": "generation:1"},
            service_generation_digest="e" * 64,
        )
        hi12 = AuthorityServiceHI12Adapter(
            service, boot_epoch=lambda: "boot:fixture",
            service_generation_digest=lambda: "e" * 64,
        )
        root_effects = RemoteConnectorEffectAuthority(
            runtime_state=lambda: state, enrollment=protected_remote,
            boot_epoch=lambda: "boot:fixture", gateway_entrypoint_artifact_id=entrypoint_artifact_id,
            gateway_entrypoint_sha256=entrypoint_digest,
            gateway=lambda uid, pid, pidfd: gateway_identity
            if (uid, pid, pidfd) == (peer_uid, peer_pid, peer_pidfd)
            else (_ for _ in ()).throw(ValueError("foreign peer")),
            role_proof=lambda _identity: role_proof,
            session_current=lambda _binding, _operation, _sequence: True,
            hi12=hi12,
        )

        def authorize(current_binding, operation, payload, sequence, maximum_bytes=0):
            return root_effects.issue_remote_connector_effect(
                current_binding, operation, payload, sequence, maximum_bytes,
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            )

        backend = RemoteServiceConnectorBackend(
            self.connector, validate_binding=lambda *_: True,
            consume_effect=root_effects.consume_remote_connector_effect,
        )
        open_payload = open_request_bytes(
            enrollment_id="enrollment:fixture", generation="generation:1",
            target_id="xpra-native", route_id="xpra-http", session_id=session_id,
            deadline=lease_deadline,
        )
        denied_backend = RemoteServiceConnectorBackend(
            self.connector, validate_binding=lambda *_: True,
            consume_effect=lambda *_args, **_kwargs: False,
        )
        with self.assertRaises(AuthorityDenied):
            denied_backend.open(
                binding,
                authorization=authorize(binding, "connector.open", open_payload, 0),
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            )
        self.assertFalse(self.accepted.wait(0.05), "denied HI12 open reached the service socket")

        opened = backend.open(
            binding,
            authorization=authorize(binding, "connector.open", open_payload, 0),
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
        )
        self.assertTrue(self.accepted.wait(2))

        request = b"GET /client/index.html HTTP/1.1\r\nHost: attacker.invalid\r\n\r\n"
        binding = replace(binding, connector_handle=opened, next_sequence=0,
                          frame_deadline_monotonic=time.monotonic() + 5)
        write_body = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                      "connector_id": opened, "session_id": session_id,
                      "generation": "generation:1", "deadline": binding.frame_deadline_monotonic,
                      "sequence": 0, "data_b64": __import__("base64").b64encode(request).decode("ascii")}
        write_payload = json.dumps(write_body, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(backend.write(
            binding, opened, 0, request,
            authorization=authorize(binding, "connector.write", write_payload, 0, len(request)),
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd, cancelled=lambda: False,
        ), len(request))

        binding = replace(binding, next_sequence=1, frame_deadline_monotonic=time.monotonic() + 5)
        read_body = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                     "connector_id": opened, "session_id": session_id,
                     "generation": "generation:1", "deadline": binding.frame_deadline_monotonic,
                     "sequence": 1, "max_bytes": 1024}
        read_payload = json.dumps(read_body, sort_keys=True, separators=(",", ":")).encode()
        reply, eof = backend.read(
            binding, opened, 1, 1024,
            authorization=authorize(binding, "connector.read", read_payload, 1, 1024),
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd, cancelled=lambda: False,
        )
        expected = (b"GET /client/index.html HTTP/1.1\r\nHost: 127.0.0.1:" + str(self.port).encode()
                    + b"\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        self.assertFalse(eof)
        self.assertEqual(reply, expected)
        self.assertEqual(bytes(self.received), expected)

        binding = replace(binding, next_sequence=2, frame_deadline_monotonic=time.monotonic() + 5)
        close_body = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                      "connector_id": opened, "session_id": session_id,
                      "generation": "generation:1", "deadline": binding.frame_deadline_monotonic, "sequence": 2}
        close_payload = json.dumps(close_body, sort_keys=True, separators=(",", ":")).encode()
        backend.close(binding, opened,
                      authorization=authorize(binding, "connector.close", close_payload, 2),
                      peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        self.assertNotIn(opened, self.connector._streams)
        self.assertEqual(len(service._nonces), 4)


    def test_root_setup_probe_uses_exact_asset_id_and_hi12_before_socket_effects(self):
        import hashlib
        from dataclasses import replace
        from types import SimpleNamespace
        from hermes_installer.authority.remote_probe_connector_authority import (
            RootSetupProbeBinding, SetupProbeConnectorAuthority,
        )
        from hermes_installer.authority.remote_connector_authority import AuthorityServiceHI12Adapter
        from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
        from hermes_installer.authority.types import Sensitivity
        from hermes_installer.service_connector import SetupProbeConnectorBackend

        path = "/client/index.html"
        asset_id = hashlib.sha256(b"hermes-client-asset-v1\0" + path.encode()).hexdigest()
        handle = __import__("secrets").token_urlsafe(32)
        now = time.monotonic()
        state = {
            "binding": RootSetupProbeBinding(
                probe_handle=handle, setup_transaction_handle="setup:fixture",
                setup_transaction_digest="a" * 64, setup_actor_identity_digest="b" * 64,
                probe_actor_identity_digest="c" * 64, setup_profile_id="setup-profile",
                setup_generation="setup-gen", setup_enrollment_id="setup-enroll",
                setup_role_sha256="d" * 64, probe_enrollment_id="probe-enroll",
                probe_profile_id="probe-profile", probe_generation="probe-gen",
                probe_role_sha256="e" * 64, gateway_identity_digest="f" * 64,
                gateway_profile_id="gateway-profile", gateway_generation="gateway-gen",
                gateway_enrollment_id="gateway-enroll", native_identity_digest="1" * 64,
                native_enrollment_id="enrollment:fixture", native_profile_id="hermes-desktop",
                native_generation="generation:1", enrollment_id="enrollment:fixture",
                target_id="xpra-native", connector_target_id="xpra-native",
                approved_route_ids=("xpra-http", "xpra-websocket"), asset_ids=(asset_id,),
                selected_action="asset-get", selected_asset_id=asset_id,
                session_id="setup-probe:nonce-fixture", next_sequence=0,
                connector_handle=None, effect_sequence=0,
                policy_revision="policy:fixture", policy_config_digest="2" * 64,
                service_generation_digest="3" * 64, principal_id="principal:fixture",
                issued_monotonic=now - 0.01, expires_monotonic=now + 20,
                frame_deadline_monotonic=now + 4, cancelled=lambda: False,
            ),
            "connector": None,
        }

        class Policy:
            def classify(self, *, purpose, intent, source_contexts, binding):
                return Sensitivity.PRIVATE, "4" * 64
            def allow_effect(self, *, context, rule, request_digest, retry_index):
                return context.sensitivity is Sensitivity.PRIVATE and retry_index == 0

        operations = ("connector.open", "connector.read", "connector.write", "connector.close")
        def make_hi12(*, omit_open=False):
            active = [operation for operation in operations if not (omit_open and operation == "connector.open")]
            rules = {("hermes-service-connect", operation, "xpra-native"):
                     EffectRule("hermes-service-connect", operation, "xpra-native") for operation in active}
            handlers = {(operation, "xpra-native"):
                        (lambda **_: {"status": 200, "body": b"", "headers": {}, "receipt_id": "fixture"})
                        for operation in active}
            service = AuthorityService(
                signing_key=b"p" * 32, key_id="setup-probe-fixture",
                bindings_by_uid={1234: PrincipalBinding(
                    1234, "principal:fixture", "hermes-desktop", "namespace:fixture",
                    frozenset({"hermes-service-connect"}))},
                rules=rules, handlers=handlers, policy=Policy(),
                profile_generations={"hermes-desktop": "generation:1"},
                service_generation_digest="3" * 64)
            return AuthorityServiceHI12Adapter(
                service, boot_epoch=lambda: "fixture-boot",
                service_generation_digest=lambda: "3" * 64), service

        def resolve(handle_arg, uid, pid, pidfd):
            if (handle_arg, uid, pid, pidfd) != (handle, 1234, os.getpid(), self.pidfd):
                raise ValueError("wrong probe peer")
            return state["binding"]

        def advance(handle_arg, expected_effect, expected_frame, operation,
                    connector_id, uid, pid, pidfd):
            if (handle_arg != handle or expected_effect != state["binding"].effect_sequence
                    or expected_frame != state["binding"].next_sequence
                    or uid != 1234 or pid != os.getpid() or pidfd != self.pidfd):
                return False
            if operation == "connector.open":
                if expected_effect != 0 or expected_frame != 0 or state["connector"] is not None:
                    return False
                state["connector"] = connector_id
                state["binding"] = replace(state["binding"], connector_handle=connector_id)
            elif connector_id != state["connector"]:
                return False
            if operation in {"connector.read", "connector.write"}:
                state["binding"] = replace(state["binding"], next_sequence=expected_frame + 1)
            state["binding"] = replace(state["binding"], effect_sequence=expected_effect + 1)
            return True

        hi12, service = make_hi12()
        authority = SetupProbeConnectorAuthority(
            resolve_binding=resolve, hi12=hi12, boot_epoch=lambda: "fixture-boot",
            advance_sequence=advance)

        self.http_response_mode = True

        class Catalog:
            def resolve_connector_route(self, enrollment, generation, target, route):
                return SimpleNamespace(enrollment_id=enrollment, generation=generation,
                    target_id=target, route_id=route, profile_id="hermes-desktop",
                    namespace_identity="net:fixture")
        class ProcessManager:
            def resolve_namespace_lease(self, binding):
                return SimpleNamespace(namespace_fd=-1, pidfd=self_pidfd, uid=1234,
                    cgroup_identity="fixture-cgroup", generation="generation:1",
                    namespace_identity="net:fixture", process_id="root-managed",
                    close=lambda: None)
        self_pidfd = self.pidfd
        backend = SetupProbeConnectorBackend(
            self.connector, catalog=Catalog(), process_manager=ProcessManager(),
            probe_authority=authority, resolve_probe_connector_binding=resolve,
            resolve_probe_asset_path=lambda binding, selected: path if selected == asset_id else (_ for _ in ()).throw(ValueError()),
        )
        denied_hi12, _denied_service = make_hi12(omit_open=True)
        denied_authority = SetupProbeConnectorAuthority(
            resolve_binding=resolve, hi12=denied_hi12, boot_epoch=lambda: "fixture-boot",
            advance_sequence=advance)
        denied_backend = SetupProbeConnectorBackend(
            self.connector, catalog=Catalog(), process_manager=ProcessManager(),
            probe_authority=denied_authority, resolve_probe_connector_binding=resolve,
            resolve_probe_asset_path=lambda binding, selected: path if selected == asset_id else (_ for _ in ()).throw(ValueError()),
        )
        try:
            with self.assertRaises(AuthorityDenied):
                backend.read_asset(handle, "4" * 64, "GET", peer_uid=1234,
                                   peer_pid=os.getpid(), peer_pidfd=self.pidfd)
            self.assertFalse(self.received, "a mismatched selected asset must not open the service socket")
            with self.assertRaises(AuthorityDenied):
                denied_backend.read_asset(handle, asset_id, "GET", peer_uid=1234,
                                          peer_pid=os.getpid(), peer_pidfd=self.pidfd)
            self.assertFalse(self.received, "a denied HI12 open must not connect to the service socket")
            result = backend.read_asset(handle, asset_id, "GET", peer_uid=1234,
                                        peer_pid=os.getpid(), peer_pidfd=self.pidfd)
            self.assertEqual((result.status, result.body), (200, b"hello"))
            self.assertEqual(len(service._nonces), 4,
                             "open/write/read/close each spend a real AuthorityService HI12 nonce")
            self.assertTrue(bytes(self.received).startswith(b"GET /client/index.html HTTP/1.1\r\nHost: 127.0.0.1:"))
            self.assertFalse(self.connector._streams)
        finally:
            self.http_response_mode = False


class FixedConnectorProtocolContracts(unittest.TestCase):
    def test_remote_backend_requires_root_current_session_binding_before_effect(self):
        from types import SimpleNamespace
        from hermes_installer.service_connector import RemoteServiceConnectorBackend

        identity = SimpleNamespace(uid=1234, pid=os.getpid(), profile_id="gateway-profile",
                                   generation="gateway-generation")
        binding = SimpleNamespace(
            gateway_identity=identity, gateway_profile_id="gateway-profile",
            gateway_generation="gateway-generation", session_id="session:root",
            target_id="xpra-native", route_id="xpra-http", action="asset",
            enrollment_id="enrollment:root", native_generation="native-generation",
            lease_expires_monotonic=time.monotonic() + 30,
            frame_deadline_monotonic=time.monotonic() + 5,
        )
        backend = RemoteServiceConnectorBackend(
            connector=None, validate_binding=lambda *_args: False,
            consume_effect=lambda *_args, **_kwargs: True)
        with self.assertRaises(AuthorityDenied):
            backend.open(binding, authorization=object(), peer_uid=1234, peer_pid=os.getpid(), peer_pidfd=1)

    def test_xpra_requests_are_limited_to_pinned_get_head_assets(self):
        route = ROUTES[("xpra-native", "xpra-http")]
        accepted = _parse_http_frame(
            b"GET /client/index.html HTTP/1.1\r\nHost: attacker.invalid\r\nAccept: text/html\r\n\r\n", route)
        self.assertIn(b"Host: 127.0.0.1:14500\r\n", accepted)
        for request in (
            b"POST /client/index.html HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            b"GET /client/index.html?host=evil HTTP/1.1\r\n\r\n",
            b"GET /client/not-pinned.js HTTP/1.1\r\n\r\n",
            b"GET /client/index.html HTTP/1.1\r\nAuthorization: Bearer x\r\n\r\n",
        ):
            with self.assertRaises(AuthorityDenied):
                _parse_http_frame(request, route)

    def test_hi13_remote_stream_uses_only_root_opaque_session_api(self):
        expiry = time.monotonic() + 30
        renewed_expiry = [expiry]
        def wire(value):
            from types import SimpleNamespace
            return SimpleNamespace(to_wire=lambda: value)
        class RootAuthority:
            calls = []
            def open_remote_connector(self, handle):
                self.calls.append(("open", handle))
                return wire({"schema": 1, "session_id": "session:root", "connector_handle": "c" * 24,
                        "generation": "generation:root", "route_id": "xpra-websocket",
                        "expires_monotonic": expiry})
            def write_remote_connector(self, handle, connector, sequence, data):
                self.calls.append(("write", handle, connector, sequence, data))
                return wire({"schema": 1, "session_id": "session:root", "sequence": sequence,
                             "accepted_bytes": len(data), "expires_monotonic": renewed_expiry[0]})
            def read_remote_connector(self, handle, connector, sequence, maximum):
                self.calls.append(("read", handle, connector, sequence, maximum))
                return wire({"schema": 1, "session_id": "session:root", "sequence": sequence,
                        "data_bytes": __import__("base64").b64encode(b"binary").decode("ascii"),
                        "eof": False, "expires_monotonic": renewed_expiry[0]})
            def close_remote_connector(self, handle, connector):
                self.calls.append(("close", handle, connector))
                return wire({"schema": 1, "session_id": "session:root", "state": "closed"})
        authority = RootAuthority()
        client = ServiceConnectorClient(authority, "r" * 32)
        stream = client.open()
        self.assertEqual(stream.route_id, "xpra-websocket")
        self.assertEqual(stream.write(b"frame"), 5)
        self.assertEqual(stream.read(64), b"binary")
        renewed_expiry[0] = expiry + 10
        self.assertEqual(stream.read(64), b"binary")
        self.assertEqual(stream.expires_monotonic, expiry + 10)
        stream.close()
        self.assertEqual([item[0] for item in authority.calls], ["open", "write", "read", "read", "close"])
        self.assertEqual(authority.calls[1][1:4], ("r" * 32, "c" * 24, 0))

    def test_colibri_allows_only_uncredentialed_chat_completion(self):
        route = ROUTES[("colibri-main", "colibri-openai-v1")]
        frame = b'{"model":"enrolled","messages":[],"stream":false}'
        request = (b"POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\n"
                   + f"Content-Length: {len(frame)}\r\n\r\n".encode() + frame)
        self.assertIn(b"POST /v1/chat/completions", _parse_http_frame(request, route))
        for request in (
            b"GET /health HTTP/1.1\r\n\r\n",
            b"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer x\r\n"
            b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        ):
            with self.assertRaises(AuthorityDenied):
                _parse_http_frame(request, route)


if __name__ == "__main__":
    unittest.main()
