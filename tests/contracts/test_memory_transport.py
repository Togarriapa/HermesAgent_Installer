"""Legacy raw HTTP path is closed; only the compound executor can be wired."""
import unittest

from hermes_installer.memory.transport import MemoryServiceIPC, MemoryTransportUnavailable


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


if __name__ == "__main__":
    unittest.main()
