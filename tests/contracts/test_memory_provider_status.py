"""Service liveness and semantic memory readiness are separate claims."""
import json
import unittest
from types import SimpleNamespace

from hermes_installer.memory.providers import BrokerMemoryProvider, MemoryProviderError


class _Broker:
    def __init__(self, result):
        self.result = result

    def context(self, **kwargs):
        source = kwargs["source_contexts"][0]
        return SimpleNamespace(**{
            "profile_id": source.profile_id, "namespace_id": source.namespace_id,
            **kwargs,
        })

    def authorize_effect(self, context, **kwargs):
        return (context, kwargs)

    def memory_request(self, grant, **kwargs):
        return SimpleNamespace(status=200,
                               body=json.dumps(self.result).encode("utf-8"))


class _Provider(BrokerMemoryProvider):
    name = "openviking"


class MemoryProviderStatusTests(unittest.TestCase):
    def setUp(self):
        self.context = SimpleNamespace(profile_id="profile-a", namespace_id="namespace-a",
                                       trace_id="trace-a")

    def test_liveness_does_not_promote_service_to_ready(self):
        provider = _Provider(_Broker({
            "service_status": "live_unqualified", "functional_memory_verified": False,
        }))

        status = provider.doctor(self.context)

        self.assertTrue(status.service_live)
        self.assertFalse(status.service_ready)
        self.assertFalse(status.available)
        self.assertFalse(status.functional_memory_verified)

    def test_readiness_is_not_functional_memory_acceptance(self):
        provider = _Provider(_Broker({
            "service_status": "ready", "functional_memory_verified": False,
        }))

        status = provider.doctor(self.context)

        self.assertTrue(status.service_live)
        self.assertTrue(status.service_ready)
        self.assertFalse(status.available)
        self.assertFalse(status.functional_memory_verified)

    def test_doctor_rejects_untyped_or_functional_claims(self):
        for result in (
            {"healthy": True},
            {"service_status": "ready", "functional_memory_verified": True},
            {"service_status": "unknown", "functional_memory_verified": False},
        ):
            with self.subTest(result=result):
                with self.assertRaises(MemoryProviderError):
                    _Provider(_Broker(result)).doctor(self.context)


if __name__ == "__main__":
    unittest.main()
