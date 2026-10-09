"""Pinned Hermes hook registration and nonblocking memory queue contracts."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.memory import native_plugin


class AuthorityFixture:
    def __init__(self):
        self.grants = []
        self.enqueued = []
        self.requests = []

    def context(self, *, purpose, intent, **kwargs):
        return SimpleNamespace(profile_id="profile-a", namespace_id="namespace-a",
                               purpose=purpose, trace_id=intent)

    def authorize_effect(self, context, *, capability, target, recipient=None):
        grant = {"capability": capability, "target": target, "context": context}
        self.grants.append(grant)
        return grant

    def memory_enqueue(self, grant, *, target, request_digest, payload, timeout, cancelled=None):
        self.assert_payload(grant, target, request_digest, payload, timeout, "enqueue")
        self.enqueued.append((grant, payload))
        return SimpleNamespace(status=202, body=b'{"accepted":true}', receipt_id="receipt-1")

    def memory_request(self, grant, *, target, request_digest, payload, timeout, cancelled=None):
        self.assert_payload(grant, target, request_digest, payload, timeout, "search")
        self.requests.append((grant, payload))
        body = {"records": [
            {"profile": "profile-a", "namespace": "namespace-a", "text": "private synthetic"},
            {"profile": "profile-b", "namespace": "namespace-b", "text": "sibling secret"},
        ]}
        return SimpleNamespace(status=200, body=json.dumps(body).encode(), receipt_id="search-1")

    @staticmethod
    def assert_payload(grant, target, digest, payload, timeout, action):
        assert target.endswith(":" + action)
        assert grant["target"] == target
        assert digest == hashlib.sha256(payload).hexdigest()
        assert "://" not in target
        assert 0 < timeout <= 2


class NativeMemoryPluginTests(unittest.TestCase):
    def _installed_provider(self, directory, authority):
        target = Path(directory) / "openviking"
        target.mkdir()
        source = Path(native_plugin.__file__)
        (target / "__init__.py").write_bytes(source.read_bytes())
        spec = importlib.util.spec_from_file_location("openviking", target / "__init__.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.HermesMemoryProvider(authority=authority)

    def test_sync_turn_queues_once_without_running_data_plane(self):
        authority = AuthorityFixture()
        with tempfile.TemporaryDirectory() as temporary:
            provider = self._installed_provider(temporary, authority)
            self.assertEqual(provider.name, "openviking")
            provider.initialize("session-1", hermes_home=temporary)
            provider.sync_turn("synthetic user fact", "short reply", session_id="session-1")
        self.assertEqual(len(authority.enqueued), 1)
        self.assertEqual(authority.requests, [])
        grant, payload = authority.enqueued[0]
        self.assertEqual(grant["capability"], "memory-capture")
        event = json.loads(payload)
        self.assertEqual((event["profile"], event["namespace"]), ("profile-a", "namespace-a"))
        self.assertEqual(event["user_content"], "synthetic user fact")
        self.assertNotIn("credential", json.dumps(event).lower())

    def test_prefetch_filters_any_cross_profile_or_namespace_result(self):
        authority = AuthorityFixture()
        with tempfile.TemporaryDirectory() as temporary:
            provider = self._installed_provider(temporary, authority)
            provider.initialize("session-1", hermes_home=temporary)
            result = provider.prefetch("synthetic", session_id="session-1")
        self.assertEqual(result, "private synthetic")
        self.assertEqual(len(authority.requests), 1)
        self.assertEqual(authority.grants[0]["capability"], "memory-retrieval")

    def test_register_uses_native_memory_provider_registration(self):
        captured = []
        native_plugin.register(SimpleNamespace(register_memory_provider=captured.append))
        self.assertEqual(len(captured), 1)
        self.assertTrue(hasattr(captured[0], "sync_turn"))


if __name__ == "__main__":
    unittest.main()
