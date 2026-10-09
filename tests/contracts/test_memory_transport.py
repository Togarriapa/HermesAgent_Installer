"""Fixed memory HTTP framing and connector denial tests (SK01, SK-T01)."""
import json
import time
import unittest

from hermes_installer.memory.enrollment import MemoryServiceEnrollment, ROUTES, SOURCE_PINS
from hermes_installer.memory.transport import (
    MemoryServiceIPC, MemoryTransportDenied, MemoryTransportUnavailable,
)


class Context:
    profile_id = "profile-one"
    namespace_id = "namespace-one"
    principal_id = "principal-one"
    trace_id = "trace-one"


class Authorization:
    pass


class Stream:
    def __init__(self, response):
        self.response = response
        self.writes = []
        self.closed = False

    def write(self, data):
        self.writes.append(data)

    def read(self, max_bytes):
        if self.response is None:
            return b""
        data, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return data

    def close(self):
        self.closed = True


class Connector:
    def __init__(self, stream):
        self.stream = stream
        self.opens = []

    def open(self, *args):
        self.opens.append(args)
        return self.stream


def enrollment():
    provider, variant = "agentmemory", "default"
    routes = ROUTES[provider][variant]
    return MemoryServiceEnrollment.from_protected_record({
        "target_id": "memory-agentmemory:profile-one",
        "provider": provider,
        "backend_variant": variant,
        "profile_id": "profile-one",
        "principal_id": "principal-one",
        "service_enrollment_id": "memory-service-one",
        "source_revision": SOURCE_PINS[provider],
        "service_generation": "generation-eight",
        "namespace_identity": "namespace-one",
        "literal_loopback_port": 3111,
        "fixed_route_map": {
            key: {"method": route.method, "path": route.path, "body": route.body}
            for key, route in routes.items()
        },
        "data_root_id": "memory-data-one",
        "auth_reference_id": "vault-ref-one",
        "fixed_project_account_user_scope": {
            "project_id": "project-one", "account_id": "account-one",
            "user_id": "profile-one",
        },
        "memory_owner_generation": 3,
        "private_extraction_embedding_routes": {
            "extract": "private-extract-one", "embed": "private-embed-one",
        },
        "background_consent_revision": "memory-consent-v1",
        "limits": {
            "request_bytes": 262144, "response_bytes": 2097152,
            "result_limit": 100, "operation_timeout_seconds": 15,
            "whole_compound_timeout_seconds": 60,
        },
    })


def make_ipc(stream, calls):
    client = Connector(stream)

    def factory(**kwargs):
        calls.append(kwargs)
        return client

    return MemoryServiceIPC(
        {("profile-one", "namespace-one", "agentmemory"): enrollment()},
        factory), client


def response(status=200, body=b'{"healthy":true}', extra_headers=b""):
    return (f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n".encode() + extra_headers
            + b"Connection: close\r\n\r\n" + body)


class MemoryTransportTests(unittest.TestCase):
    def test_frames_only_fixed_route_and_opens_enrolled_target_generation(self):
        calls = []
        ipc, client = make_ipc(Stream(response()), calls)
        result = ipc.request(context=Context(), authorization=Authorization(),
            service_id="memory-service-one", service_generation="generation-eight",
            provider="agentmemory", route_id="agentmemory-ready",
            session_id="trace-one", deadline_monotonic=time.monotonic()+5,
            payload=b'{"schema":1}', timeout=2, peer_pid=1001,
            peer_pidfd=None, cancelled=lambda: False)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, b'{"healthy":true}')
        self.assertEqual(client.opens, [("memory-service-one", 8,
            "memory-agentmemory:profile-one", "agentmemory-ready", "trace-one",
            client.opens[0][-1])])
        self.assertEqual(len(client.stream.writes), 1)
        request = client.stream.writes[0]
        self.assertTrue(request.startswith(b"GET /agentmemory/livez HTTP/1.1\r\n"))
        self.assertIn(b"Host: 127.0.0.1:3111\r\n", request)
        self.assertNotIn(b"Authorization:", request)
        self.assertTrue(client.stream.closed)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0]["request_digest"]), 64)

    def test_wrong_service_generation_or_principal_denies_before_connector(self):
        for changes in ({"service_generation": "generation-seven"}, {"principal": "sibling"}):
            calls = []
            ipc, _ = make_ipc(Stream(response()), calls)
            context = Context()
            if "principal" in changes:
                context.principal_id = changes["principal"]
            with self.assertRaises(MemoryTransportDenied):
                ipc.request(context=context, authorization=Authorization(),
                    service_id="memory-service-one",
                    service_generation=changes.get("service_generation", 8),
                    provider="agentmemory", route_id="agentmemory-ready",
                    session_id="trace-one", deadline_monotonic=time.monotonic()+5,
                    payload=b'{"schema":1}', timeout=2, peer_pid=1001,
                    peer_pidfd=None, cancelled=lambda: False)
            self.assertEqual(calls, [])

    def test_unknown_route_redirect_and_oversized_response_fail_closed(self):
        calls = []
        ipc, _ = make_ipc(Stream(response()), calls)
        args = dict(context=Context(), authorization=Authorization(),
            service_id="memory-service-one", service_generation=8,
            provider="agentmemory", session_id="trace-one",
            deadline_monotonic=time.monotonic()+5, payload=b'{"schema":1}',
            timeout=2, peer_pid=1001, peer_pidfd=None, cancelled=lambda: False)
        with self.assertRaises(MemoryTransportDenied):
            ipc.request(route_id="openviking-find", **args)
        self.assertEqual(calls, [])
        ipc, _ = make_ipc(Stream(response(302)), calls)
        with self.assertRaises(MemoryTransportDenied):
            ipc.request(route_id="agentmemory-ready", **args)
        oversized = b"x" * (2 * 1024 * 1024 + 1)
        ipc, _ = make_ipc(Stream(response(body=oversized)), calls)
        with self.assertRaises(MemoryTransportUnavailable):
            ipc.request(route_id="agentmemory-ready", **args)


if __name__ == "__main__":
    unittest.main()
