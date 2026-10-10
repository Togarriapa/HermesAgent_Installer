"""Pinned Hermes hook registration and nonblocking memory queue contracts."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.client import AuthorityClient
from hermes_installer.authority.types import HostContext, Sensitivity
from hermes_installer.memory import native_plugin


class AuthorityFixture(AuthorityClient):
    def __init__(self):
        super().__init__(Path("/fixture/authority.sock"), server_uid=0, monotonic=lambda: 1.0)
        self.grants = []
        self.enqueued = []
        self.requests = []
        self.context_requests = []

    def _rpc(self, operation, payload, *, timeout=None, cancelled=None):
        if operation != "issue_context":
            raise AssertionError("unexpected authority RPC")
        self.context_requests.append(payload)
        claims = HostContext(
            principal_id="principal-a", profile_id="profile-a", namespace_id="namespace-a",
            uid=1000, purpose=payload["purpose"], intent_id=payload["intent"],
            trace_id=payload.get("trace_id") or "trace-a", sensitivity=Sensitivity.UNKNOWN,
            lineage_hash="0" * 64, policy_revision="fixture-policy", capabilities=frozenset(),
            issued_at_monotonic=1.0, monotonic_expires_at=31.0, nonce="nonce-a",
            grant_id="grant-a", signature="fixture-signature",
            final_payload_digest=payload.get("final_payload_digest"),
            operation=payload["operation"],
        )
        return claims.to_wire()

    def authorize_effect(self, context, *, capability, target, request_digest, recipient=None):
        grant = {"capability": capability, "target": target, "context": context, "request_digest": request_digest}
        self.grants.append(grant)
        return grant

    def memory_enqueue(self, grant, *, target, request_digest, payload, timeout, cancelled=None):
        self.assert_payload(grant, target, request_digest, payload, timeout, "enqueue")
        self.enqueued.append((grant, payload))
        return SimpleNamespace(status=202, body=b'{"queued":true,"receipt_id":"job-receipt-1"}', receipt_id="transport-receipt-1")

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
        assert grant["request_digest"] == digest
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

    def test_native_text_hooks_cannot_enqueue_unobserved_capture_events(self):
        authority = AuthorityFixture()
        with tempfile.TemporaryDirectory() as temporary:
            provider = self._installed_provider(temporary, authority)
            self.assertEqual(provider.name, "openviking")
            provider.initialize("session-1", hermes_home=temporary)
            provider.sync_turn("synthetic user fact", "short reply", session_id="session-1")
            provider.on_memory_write("add", "memory", "synthetic write")
        self.assertEqual(authority.enqueued, [])
        self.assertEqual(authority.requests, [])
        self.assertEqual(provider._last_hook_status, "unavailable:source_event_missing")
        self.assertEqual(authority.context_requests, [])

    def test_search_returns_only_root_scoped_records(self):
        authority = AuthorityFixture()
        with tempfile.TemporaryDirectory() as temporary:
            provider = self._installed_provider(temporary, authority)
            provider.initialize("session-1", hermes_home=temporary)
            authority.memory_request = lambda grant, **kwargs: SimpleNamespace(
                status=200,
                body=json.dumps({"records": [{"profile": "profile-a",
                    "namespace": "namespace-a", "id": "memory-1",
                    "source": "openviking", "text": "synthetic private fact"}]}).encode(),
                receipt_id="search-1")
            result = provider.prefetch("synthetic", session_id="session-1")
        self.assertEqual(result, "synthetic private fact")

    def test_prefetch_fails_closed_on_cross_profile_or_namespace_result(self):
        authority = AuthorityFixture()
        with tempfile.TemporaryDirectory() as temporary:
            provider = self._installed_provider(temporary, authority)
            provider.initialize("session-1", hermes_home=temporary)
            result = provider.prefetch("synthetic", session_id="session-1")
        self.assertEqual(result, "")
        self.assertEqual(len(authority.requests), 1)
        self.assertEqual(authority.grants[0]["capability"], "memory-retrieval")
        self.assertEqual(authority.context_requests[-1]["operation"], "memory.search")
        self.assertEqual(authority.context_requests[-1]["final_payload_digest"],
                         hashlib.sha256(authority.requests[-1][1]).hexdigest())

    def test_provider_adapter_uses_real_authority_context_contract(self):
        from hermes_installer.memory.providers import OpenVikingProvider
        authority = AuthorityFixture()
        source = authority.context(
            purpose="memory-retrieval", intent="synthetic-search",
            operation="memory.search", final_payload_digest=hashlib.sha256(b"source").hexdigest())

        class Response:
            status = 200
            body = b'{"records":[]}'

        def request(grant, *, target, request_digest, payload, timeout, cancelled=None):
            authority.assert_payload(grant, target, request_digest, payload, timeout, "search")
            authority.requests.append((grant, payload))
            return Response()

        authority.memory_request = request
        provider = OpenVikingProvider(authority, timeout=2.0)
        self.assertEqual(provider.search("namespace-a", "synthetic", 1, context=source), [])
        issued = authority.context_requests[-1]
        self.assertEqual(issued["operation"], "memory.search")
        self.assertEqual(issued["final_payload_digest"],
                         hashlib.sha256(authority.requests[-1][1]).hexdigest())

    def test_register_uses_native_memory_provider_registration(self):
        captured = []
        native_plugin.register(SimpleNamespace(register_memory_provider=captured.append))
        self.assertEqual(len(captured), 1)
        self.assertTrue(hasattr(captured[0], "sync_turn"))


if __name__ == "__main__":
    unittest.main()
