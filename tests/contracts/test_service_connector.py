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
        def echo():
            peer, _ = self.listener.accept()
            self.accepted.set()
            try:
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
                 "session_id": "session:fixture", "sequence": 0,
                 "data_b64": __import__("base64").b64encode(request).decode("ascii")}
        _call(self.connector, "connector.write", json.dumps(write, sort_keys=True, separators=(",", ":")).encode(), pidfd=self.pidfd)
        read = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http", "connector_id": opened["connector_id"],
                "session_id": "session:fixture", "sequence": 1, "max_bytes": 1024}
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
                              "sequence": 0, "max_bytes": 16}, sort_keys=True,
                             separators=(",", ":")).encode()
        with self.assertRaises(AuthorityDenied):
            _call(self.connector, "connector.read", payload, pid=os.getpid() + 1, pidfd=self.pidfd)

    def test_cancelled_read_closes_retained_stream_and_peer(self):
        opened = self._open()
        payload = json.dumps({"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                              "connector_id": opened["connector_id"], "session_id": "session:fixture",
                              "sequence": 0, "max_bytes": 16}, sort_keys=True,
                             separators=(",", ":")).encode()
        with self.assertRaises(AuthorityDenied):
            _call(self.connector, "connector.read", payload, pidfd=self.pidfd, cancelled=lambda: True)
        self.assertNotIn(opened["connector_id"], self.connector._streams)


class FixedConnectorProtocolContracts(unittest.TestCase):
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
        class RootAuthority:
            calls = []
            def open_remote_connector(self, handle):
                self.calls.append(("open", handle))
                return {"schema": 1, "session_id": "session:root", "connector_handle": "c" * 24,
                        "generation": "generation:root", "route_id": "xpra-websocket",
                        "expires_monotonic": expiry}
            def write_remote_connector(self, handle, connector, sequence, data):
                self.calls.append(("write", handle, connector, sequence, data))
                return {"schema": 1, "session_id": "session:root", "sequence": sequence,
                        "accepted_bytes": len(data), "expires_monotonic": expiry}
            def read_remote_connector(self, handle, connector, sequence, maximum):
                self.calls.append(("read", handle, connector, sequence, maximum))
                return {"schema": 1, "session_id": "session:root", "sequence": sequence,
                        "data_bytes": b"binary", "eof": False, "expires_monotonic": expiry}
            def close_remote_connector(self, handle, connector):
                self.calls.append(("close", handle, connector))
                return {"schema": 1, "session_id": "session:root", "state": "closed"}
        authority = RootAuthority()
        client = ServiceConnectorClient(authority, "r" * 32)
        stream = client.open()
        self.assertEqual(stream.route_id, "xpra-websocket")
        self.assertEqual(stream.write(b"frame"), 5)
        self.assertEqual(stream.read(64), b"binary")
        stream.close()
        self.assertEqual([item[0] for item in authority.calls], ["open", "write", "read", "close"])
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
