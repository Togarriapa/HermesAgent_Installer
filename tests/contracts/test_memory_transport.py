"""Retired direct HTTP memory transport cannot perform service effects."""
import time
import unittest

from hermes_installer.memory.transport import (
    MemoryServiceIPC, MemoryTransportUnavailable,
)


class MemoryTransportTests(unittest.TestCase):
    def test_direct_http_request_is_unavailable_before_connector_factory(self):
        calls = []
        def factory(**kwargs):
            calls.append(kwargs)
            raise AssertionError("retired direct transport must not open a connector")

        transport = MemoryServiceIPC({}, factory)
        with self.assertRaisesRegex(MemoryTransportUnavailable, "compound executor"):
            transport.request(
                context=object(), authorization=object(), service_id="service",
                service_generation="generation", provider="agentmemory",
                route_id="agentmemory-search", session_id="session",
                deadline_monotonic=time.monotonic() + 1, payload=b"{}",
                timeout=1, peer_pid=1, peer_pidfd=None, cancelled=lambda: False,
            )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
