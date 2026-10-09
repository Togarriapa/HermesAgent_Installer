"""Broker-bound memory effects, isolation and persistence contracts (SK-F02, SK-R0071/73/78; R0135-R0137)."""
import hashlib
import json
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.memory.lifecycle import MemoryRecord
from hermes_installer.memory.providers import AgentMemoryProvider, ClaudeMemProvider, OpenVikingProvider
from hermes_installer.memory.owner_ledger import OwnerTransitionError, SQLiteOwnerLedger


class BrokerFixture:
    """A deterministic boundary fixture; not host broker or native-service evidence."""
    def __init__(self):
        self.calls = []
        self.profile_id = "profile-a"
        self.namespace_id = "namespace-a"
        self.trace_id = "trace-a"

    def context(self, *, purpose, intent, source_contexts=(), trace_id=None, lease_seconds=30):
        return SimpleNamespace(profile_id=self.profile_id, namespace_id=self.namespace_id,
                               trace_id=trace_id or purpose, purpose=purpose, sensitivity="PRIVATE")

    def authorize_effect(self, context, *, capability, target, recipient=None, request_digest, retry_index=0, cancelled=None):
        self.calls.append(("grant", context, capability, target, request_digest))
        return (capability, target, context, request_digest)

    def memory_request(self, grant, *, target, request_digest, payload, timeout, cancelled=None):
        self.assert_request(target, request_digest, payload, timeout)
        capability, granted_target, context, granted_digest = grant
        assert request_digest == granted_digest
        self.calls.append(("request", context, capability, granted_target, payload))
        op = target.rsplit(":", 1)[-1]
        body = {
            "doctor": {"healthy": True, "revision": "fixture"},
            "extract": {"facts": [{"text": "synthetic fact"}]},
            "embed": {"embeddings": [[0.0, 1.0]]},
            "capture": {"stored": True},
            "search": {"records": [{"id": "r1", "namespace": "namespace-a",
                "profile": "profile-a", "source": "user", "text": "synthetic fact",
                "provenance": ["fixture"]}, {"id": "other", "namespace": "namespace-b",
                "profile": "profile-b", "source": "user", "text": "private sibling",
                "provenance": []}]},
            "export": {"records": [{"id": "r1", "namespace": "namespace-a",
                "profile": "profile-a", "source": "user", "text": "synthetic fact",
                "provenance": ["fixture"]}]},
            "delete": {"deleted": True},
            "backup": {"archive": "eA==", "sha256": hashlib.sha256(b"x").hexdigest()},
            "restore": {"restored": True},
        }[op]
        return SimpleNamespace(status=200, body=json.dumps(body).encode(), headers={}, receipt_id="fixture")

    @staticmethod
    def assert_request(target, digest, payload, timeout):
        assert target.startswith("memory:")
        assert "://" not in target
        assert digest == hashlib.sha256(payload).hexdigest()
        assert 0 < timeout <= 30


class MemoryBrokerTests(unittest.TestCase):
    def setUp(self):
        self.broker = BrokerFixture()
        self.ctx = self.broker.context(purpose="memory-capture", intent="test")

    def test_each_provider_uses_fixed_broker_and_separate_derived_authority(self):
        record = MemoryRecord("r1", "namespace-a", "profile-a", "user", "synthetic fact", ("turn-1",))
        for provider_type in (OpenVikingProvider, ClaudeMemProvider, AgentMemoryProvider):
            with self.subTest(provider=provider_type.name):
                self.broker.calls.clear()
                provider = provider_type(self.broker)
                provider.capture(record, context=self.ctx)
                targets = [call[3] for call in self.broker.calls if call[0] == "grant"]
                self.assertEqual(targets, [
                    f"memory:{provider.name}:extract",
                    f"memory:{provider.name}:embed",
                    f"memory:{provider.name}:capture",
                ])
                self.assertEqual([call[2] for call in self.broker.calls if call[0] == "grant"],
                                 ["memory-extraction", "memory-embedding", "memory-capture"])
                self.assertTrue(all(call[1] is not self.ctx for call in self.broker.calls
                                    if call[0] == "grant"))
                self.assertTrue(all(call[0] == "grant" or "://" not in call[3]
                                    for call in self.broker.calls))

    def test_search_export_delete_are_namespace_scoped_and_brokered(self):
        provider = AgentMemoryProvider(self.broker)
        found = provider.search("namespace-a", "synthetic", 10, context=self.ctx)
        self.assertEqual([r.id for r in found], ["r1"])
        exported = provider.export("namespace-a", context=self.ctx)
        self.assertEqual([r.id for r in exported], ["r1"])
        self.assertTrue(provider.remove("namespace-a", "r1", context=self.ctx))
        self.assertEqual([call[2] for call in self.broker.calls if call[0] == "grant"],
                         ["memory-retrieval", "memory-export", "memory-delete"])

    def test_backup_restore_are_separate_digest_bound_scoped_effects(self):
        provider = AgentMemoryProvider(self.broker)
        backup = provider.backup("namespace-a", context=self.ctx)
        self.assertEqual((backup.provider, backup.profile, backup.namespace),
                         ("agentmemory", "profile-a", "namespace-a"))
        provider.restore(backup, context=self.ctx)
        grants = [call for call in self.broker.calls if call[0] == "grant"]
        self.assertEqual([call[2] for call in grants], ["memory-backup", "memory-restore"])
        self.assertEqual([call[3] for call in grants],
                         ["memory:agentmemory:backup", "memory:agentmemory:restore"])
        foreign = backup.__class__(backup.provider, "profile-b", backup.namespace,
                                   backup.archive, backup.sha256, backup.lineage)
        before = len(self.broker.calls)
        with self.assertRaises(PermissionError):
            provider.restore(foreign, context=self.ctx)
        self.assertEqual(len(self.broker.calls), before)

    def test_owner_journal_persists_and_blocks_unresolved_transition(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = SQLiteOwnerLedger(Path(temporary) / "owned-memory-state")
            self.assertIsNone(ledger.get_owner("profile-a"))
            initial = ledger.begin_transition("profile-a", None, "openviking")
            with self.assertRaises(OwnerTransitionError):
                ledger.set_owner("profile-a", "claude-mem")
            with self.assertRaises(OwnerTransitionError):
                ledger.begin_transition("profile-a", "claude-mem", "openviking")
            with self.assertRaises(OwnerTransitionError):
                ledger.get_owner("profile-a")
            ledger.commit_transition("profile-a", initial, "openviking")
            self.assertEqual(ledger.get_owner("profile-a"), "openviking")
            interrupted = ledger.begin_transition("profile-a", "openviking", "claude-mem")
            with self.assertRaises(OwnerTransitionError):
                ledger.get_owner("profile-a")
            ledger.abort_transition("profile-a", interrupted)
            self.assertEqual(ledger.get_owner("profile-a"), "openviking")

    def test_grant_binds_exact_payload_and_caller_scope_cannot_expand(self):
        provider = AgentMemoryProvider(self.broker)
        original = b'{"schema":1,"namespace":"namespace-a","query":"x","limit":1}'
        altered = b'{"schema":1,"namespace":"namespace-b","query":"x","limit":1}'
        digest = hashlib.sha256(original).hexdigest()
        target = "memory:agentmemory:search"
        grant = self.broker.authorize_effect(self.ctx, capability="memory-retrieval",
                                             target=target, request_digest=digest)
        with self.assertRaises(AssertionError):
            self.broker.memory_request(grant, target=target,
                request_digest=hashlib.sha256(altered).hexdigest(), payload=altered,
                timeout=1.0)
        self.assertFalse(any(call[0] == "request" for call in self.broker.calls))
        mismatched = MemoryRecord("r2", "namespace-b", "profile-b", "user", "sibling")
        with self.assertRaises(PermissionError):
            provider.capture(mismatched, context=self.ctx)
        with self.assertRaises(PermissionError):
            provider.search("namespace-b", "q", 1, context=self.ctx)

    def test_missing_context_recursion_and_service_failure_have_no_unmediated_effect(self):
        provider = OpenVikingProvider(self.broker)
        record = MemoryRecord("r1", "namespace-a", "profile-a", "memory:generated", "generated")
        with self.assertRaises(PermissionError):
            provider.capture(record, context=self.ctx)
        with self.assertRaises(PermissionError):
            provider.search("namespace-a", "q", 10)
        self.assertEqual(self.broker.calls, [])


if __name__ == "__main__":
    unittest.main()
