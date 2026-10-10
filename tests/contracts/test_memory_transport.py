"""Legacy raw HTTP path is closed; only the compound executor can be wired."""
import unittest
import socket
import threading
from types import SimpleNamespace

from hermes_installer.memory.transport import MemoryServiceIPC, MemoryTransportUnavailable
from hermes_installer.memory.compound import MemoryServiceRequest
from hermes_installer.memory.namespace_connector import (
    MemoryNamespaceDenied, read_bounded_http_response, _frame,
)


class Context:
    profile_id = "profile-one"
    namespace_id = "namespace-one"


class ForbiddenConnectorFactory:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        raise AssertionError("raw memory connector must never open")


class MemoryTransportTests(unittest.TestCase):
    def test_raw_http_is_unavailable_before_connector_open(self):
        factory = ForbiddenConnectorFactory()
        ipc = MemoryServiceIPC({}, factory)
        with self.assertRaisesRegex(MemoryTransportUnavailable, "fixed compound executor"):
            ipc.request(
                context=Context(), authorization=object(), service_id="service-one",
                service_generation="generation-one", provider="agentmemory",
                route_id="agentmemory-search", session_id="trace-one",
                deadline_monotonic=9999999999.0, payload=b'{"schema":1}', timeout=1.0,
                peer_pid=10, peer_pidfd=None, cancelled=lambda: False,
            )
        self.assertEqual(factory.calls, [])

    def test_root_serializer_adds_only_the_enrolled_credential_codec(self):
        enrollment = SimpleNamespace(
            provider="agentmemory", fixed_route_map={"agentmemory-search": object()},
            literal_loopback_port=3111,
        )
        request = MemoryServiceRequest(
            "POST", "/agentmemory/smart-search", (), b'{"query":"synthetic"}',
            "memory-auth-profile-one",
        )
        frame = _frame(enrollment=enrollment, route_id="agentmemory-search",
                       request=request, secret="root-vault-secret", maximum_bytes=4096)
        header, body = frame.split(b"\r\n\r\n", 1)
        self.assertIn(b"Authorization: Bearer root-vault-secret", header)
        self.assertNotIn(b"X-API-Key", header)
        self.assertEqual(body, request.body)
        self.assertNotIn(b"root-vault-secret", body)

    def test_unauthed_doctor_probes_do_not_resolve_or_emit_memory_credentials(self):
        for provider, route_id, path, port in (
            ("openviking", "openviking-ready", "/ready", 1933),
            ("agentmemory", "agentmemory-ready", "/agentmemory/livez", 3111),
        ):
            with self.subTest(provider=provider):
                enrollment = SimpleNamespace(
                    provider=provider, fixed_route_map={route_id: object()},
                    literal_loopback_port=port)
                request = MemoryServiceRequest("GET", path, (("accept", "application/json"),),
                                               b"", "unused-auth-reference")
                frame = _frame(enrollment=enrollment, route_id=route_id,
                               request=request, secret=None, maximum_bytes=4096)
                header, body = frame.split(b"\r\n\r\n", 1)
                self.assertIn(f"GET {path} HTTP/1.1".encode(), header)
                self.assertNotIn(b"Authorization:", header)
                self.assertNotIn(b"X-API-Key:", header)
                self.assertNotIn(b"Content-Length:", header)
                self.assertEqual(body, b"")

    def test_bounded_response_parser_accepts_one_exact_json_frame(self):
        reader, writer = socket.socketpair()
        response = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}'
        thread = threading.Thread(target=lambda: (writer.sendall(response), writer.close()))
        thread.start()
        try:
            result = read_bounded_http_response(
                reader, maximum_body=64, deadline=10**12, cancelled=lambda: False)
        finally:
            reader.close()
            thread.join(timeout=1)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, b'{"ok":true}')

    def test_bounded_response_parser_rejects_ambiguous_and_truncated_frames(self):
        invalid = (
            b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}',
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}',
            b'HTTP/1.1 302 Found\r\nContent-Length: 2\r\n\r\n{}',
        )
        for response in invalid:
            with self.subTest(response=response[:32]):
                reader, writer = socket.socketpair()
                writer.sendall(response)
                writer.close()
                try:
                    with self.assertRaises(MemoryNamespaceDenied):
                        read_bounded_http_response(
                            reader, maximum_body=64, deadline=10**12,
                            cancelled=lambda: False)
                finally:
                    reader.close()
        reader, writer = socket.socketpair()
        writer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}')
        writer.close()
        try:
            with self.assertRaisesRegex(RuntimeError, "truncated"):
                read_bounded_http_response(
                    reader, maximum_body=64, deadline=10**12,
                    cancelled=lambda: False)
        finally:
            reader.close()


if __name__ == "__main__":
    unittest.main()
