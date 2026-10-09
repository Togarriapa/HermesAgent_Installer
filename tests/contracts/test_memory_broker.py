"""Effect and failure contracts for the root memory broker."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from hermes_installer.memory.broker import (
    BrokerDenied, BrokerUnavailable, DurableMemoryQueue, MemoryTarget, build_memory_handlers,
    canonical, ROUTE_IDS, build_memory_runtime,
)


class Context:
    def __init__(self, profile="p1", namespace="n1"):
        self.profile_id = profile
        self.namespace_id = namespace
        self.principal_id, self.uid = "principal", 1001
        self.purpose, self.intent_id = "memory-capture", "intent"
        self.sensitivity, self.policy_revision = "private", "policy1"
        self.lineage_hash = "a" * 64
        self.source_receipts, self.final_payload_digest = (), None
        self.trace_id = "trace-one"

    def to_wire(self):
        return {
            "principal_id": "principal", "profile_id": self.profile_id,
            "namespace_id": self.namespace_id, "uid": 1001,
            "purpose": "memory-capture", "intent_id": "intent",
            "trace_id": self.trace_id, "sensitivity": "private",
            "lineage_hash": self.lineage_hash, "policy_revision": "policy1",
            "capabilities": ["memory-capture"], "issued_at_monotonic": 1.0,
            "monotonic_expires_at": 20.0, "nonce": "nonce", "grant_id": "grant",
            "signature": "signed-fixture",
        }


class Grant:
    def __init__(self, context, target, digest):
        self.profile_id, self.namespace_id = context.profile_id, context.namespace_id
        self.target, self.request_digest = target, digest
        action = target.rsplit(":", 1)[-1]
        self.capability = {"doctor":"memory-retrieval","search":"memory-retrieval",
            "extract":"memory-extraction","embed":"memory-embedding","capture":"memory-capture",
            "enqueue":"memory-capture","export":"memory-export","backup":"memory-backup",
            "restore":"memory-restore","delete":"memory-delete","result":"memory-retrieval"}[action]
        self.principal_id, self.uid = context.principal_id, context.uid
        self.purpose, self.intent_id = context.purpose, context.intent_id
        self.trace_id, self.policy_revision = context.trace_id, context.policy_revision
        self.lineage_hash = context.lineage_hash
        self.sensitivity, self.source_receipts = context.sensitivity, context.source_receipts
        self.final_payload_digest = context.final_payload_digest


class IPC:
    def __init__(self):
        self.calls = []

    def request(self, **kwargs):
        self.calls.append(kwargs)
        return b'{"healthy":true,"revision":"pinned"}'


def target(profile, namespace, service):
    return MemoryTarget("agentmemory", profile, namespace, service,
                        "df3d4a83b966d8d415cb9180d5a4724b07f729dc", 1,
                        "root-data-" + profile,
                        approved_route_ids=frozenset(ROUTE_IDS["agentmemory"].values()))


def call(handler, context, action, value, *, digest_override=None, provider="agentmemory"):
    raw = canonical(value)
    grant = Grant(context, "memory:" + provider + ":" + action,
                  digest_override or hashlib.sha256(raw).hexdigest())
    return handler(context=context, authorization=grant, payload=raw, timeout=1.0,
                   peer_pid=123, cancelled=lambda: False)


class MemoryBrokerTests(unittest.TestCase):
    def test_legacy_raw_service_connector_is_never_called(self):
        t1, t2 = target("p1", "n1", "service-one"), target("p2", "n2", "service-two")
        ipc = IPC()
        owner = lambda profile: (None, 0)
        handlers = build_memory_handlers(
            targets={("p1", "n1", "agentmemory"): t1, ("p2", "n2", "agentmemory"): t2},
            owner_state=owner, queue=None, ipc=ipc)
        handler = handlers[("memory.doctor", "memory:agentmemory:doctor")]
        first = call(handler, Context(), "doctor", {"schema": 1})
        second = call(handler, Context("p2", "n2"), "doctor", {"schema": 1})
        self.assertEqual(first["status"], 503)
        self.assertEqual(second["status"], 503)
        self.assertEqual(ipc.calls, [])

    def test_payload_mutation_and_sibling_scope_fail_before_service_effect(self):
        t = target("p1", "n1", "service-one")
        ipc = IPC()
        handlers = build_memory_handlers(
            targets={("p1", "n1", "agentmemory"): t},
            owner_state=lambda _: (None, 0), queue=None, ipc=ipc)
        handler = handlers[("memory.doctor", "memory:agentmemory:doctor")]
        denied = call(handler, Context(), "doctor", {"schema": 1},
                      digest_override="0" * 64)
        self.assertEqual(denied["status"], 403)
        self.assertEqual(ipc.calls, [])
        denied_scope = call(handler, Context("p2", "n2"), "doctor", {"schema": 1})
        self.assertEqual(denied_scope["status"], 403)
        self.assertEqual(ipc.calls, [])

    def test_legacy_transport_unavailable_even_when_context_lacks_trace_id(self):
        t = target("p1", "n1", "service-one")
        ipc = IPC()
        handlers = build_memory_handlers(
            targets={("p1","n1","agentmemory"):t},
            owner_state=lambda _: (None,0), queue=None, ipc=ipc)
        context = Context()
        context.trace_id = None
        result = call(handlers[("memory.doctor","memory:agentmemory:doctor")],
                      context, "doctor", {"schema":1})
        self.assertEqual(result["status"], 503)
        self.assertEqual(ipc.calls, [])

    def test_unenrolled_opaque_route_denied_before_connector_bytes(self):
        t = MemoryTarget("agentmemory", "p1", "n1", "service-one",
            "df3d4a83b966d8d415cb9180d5a4724b07f729dc", 1, "root-data-p1",
            approved_route_ids=frozenset())
        ipc = None
        handlers = build_memory_handlers(
            targets={("p1","n1","agentmemory"):t},
            owner_state=lambda _: (None,0), queue=None, ipc=ipc)
        result = call(handlers[("memory.doctor","memory:agentmemory:doctor")],
                      Context(), "doctor", {"schema":1})
        self.assertEqual(result["status"], 403)

    def test_private_transform_is_unavailable_without_enrolled_local_engine(self):
        t = target("p1", "n1", "service-one")
        ipc = IPC()
        handlers = build_memory_handlers(
            targets={("p1", "n1", "agentmemory"): t},
            owner_state=lambda _: ("agentmemory", 1), queue=None, ipc=ipc,
            eligibility=lambda *_: True)
        handler = handlers[("memory.extract", "memory:agentmemory:extract")]
        response = call(handler, Context(), "extract", {
            "schema": 1, "record": {"id": "synthetic", "source": "fixture",
                                    "text": "a harmless synthetic fact"}})
        self.assertEqual(response["status"], 503)
        self.assertEqual(ipc.calls, [])

    def test_durable_queue_persists_signed_lineage_and_is_profile_scoped(self):
        t = target("p1", "n1", "service-one")
        consent_calls = []
        owner = lambda profile: ("agentmemory", 7)
        def consent(**kwargs):
            consent_calls.append(kwargs)
            return {"consent_id": "consent-1", "signature": "root-signed"}
        context = Context()
        with tempfile.TemporaryDirectory() as directory:
            queue = DurableMemoryQueue(Path(directory) / "queue",
                                       owner_state=owner, consent_issuer=consent)
            receipt = queue.enqueue(target=t, context=context, body={
                "schema": 1, "profile": "p1", "namespace": "n1",
                "event": "turn", "session_id": "session-1",
                "user_content": "synthetic user fact",
                "assistant_content": "synthetic response",
            })
            job = queue.claim()
            self.assertEqual(job["id"], receipt)
            self.assertEqual(job["owner_generation"], 7)
            self.assertIn(b'"lineage_hash"', job["source_context"])
            self.assertEqual(json.loads(job["consent"]), {"consent_id":"consent-1","signature":"root-signed"})
            self.assertEqual(job["consent_id"], "consent-1")
            self.assertTrue(queue.consent_active("consent-1"))
            self.assertEqual(queue.result(context, receipt)["status"], "processing")
            self.assertFalse(queue.result(Context("p2", "n2"), receipt)["found"])
            self.assertEqual(consent_calls[0]["provider_id"], "agentmemory")
            self.assertEqual(consent_calls[0]["owner_generation"], 7)

    def test_prepared_owner_transition_blocks_worker_without_consuming_job(self):
        t = target("p1", "n1", "service-one")
        with tempfile.TemporaryDirectory() as directory:
            state = {"transitioning": False, "owner": ("agentmemory", 7)}
            def owner_state(_):
                if state["transitioning"]:
                    raise RuntimeError("prepared owner transition")
                return state["owner"]
            queue = DurableMemoryQueue(Path(directory) / "queue",
                owner_state=owner_state,
                consent_issuer=lambda **_: {"consent_id":"pending-consent","signature":"signed"})
            receipt = queue.enqueue(target=t, context=Context(), body={
                "schema":1,"event":"turn","session_id":"s",
                "user_content":"synthetic","assistant_content":"synthetic"})
            state["transitioning"] = True
            self.assertIsNone(queue.claim())
            self.assertFalse(queue.consent_active("pending-consent"))
            self.assertEqual(queue.result(Context(), receipt)["status"], "queued")
            with queue._db() as db:
                stored = db.execute("SELECT event FROM jobs WHERE id=?", (receipt,)).fetchone()[0]
            self.assertIn(b"synthetic", bytes(stored))


    def test_root_runtime_stays_disabled_without_protected_state_catalog(self):
        class SignedConsent:
            def to_wire(self):
                return {"consent_id":"runtime-consent","signature":"root-signed"}
        class Authority:
            def create_background_consent(self, **_):
                return SignedConsent()
            def perform_memory_effect(self, **_):
                raise AssertionError("runtime must not start a background worker")
        t = target("p1", "n1", "service-one")
        runtime = build_memory_runtime({("p1","n1","agentmemory"):t}, Authority())
        self.assertFalse(runtime["consent_ready"])
        self.assertFalse(runtime["state_root_ready"])
        self.assertIsNone(runtime["ipc"])
        self.assertEqual(runtime["engines"], {})
        self.assertIsNone(runtime["queue"])
        with self.assertRaises(BrokerUnavailable):
            runtime["owner_state"]("p1")

    def test_root_runtime_rejects_legacy_raw_connector_factory(self):
        t = target("p1", "n1", "service-one")
        class Authority:
            def create_background_consent(self, **_):
                return {"consent_id": "consent", "signature": "signed"}
            def perform_memory_effect(self, **_):
                raise AssertionError("runtime must not start a worker")
        with self.assertRaisesRegex(ValueError, "raw memory HTTP connector factories"):
            build_memory_runtime(
                {("p1", "n1", "agentmemory"): t}, Authority(),
                connector_factory=lambda **_: IPC())

    def test_pinned_route_catalog_is_distinct_from_unavailable_raw_transport(self):
        # Fixed routes were checked against each provider's exact enrolled source.
        self.assertEqual(ROUTE_IDS["agentmemory"]["doctor"], "memory.agentmemory.livez.v1")
        self.assertEqual(ROUTE_IDS["agentmemory"]["delete"], "memory.agentmemory.forget.v1")
        self.assertEqual(ROUTE_IDS["claude-mem"]["capture"], "memory.claude-mem.create.v1")
        self.assertEqual(ROUTE_IDS["claude-mem"]["delete"], "memory.claude-mem.delete.v1")
        t = MemoryTarget("claude-mem", "p1", "n1", "claude-service",
            "fa8ab09f06aa05f958c5225cf3756ce52a3ebb96", 2, "claude-data-p1",
            approved_route_ids=frozenset(ROUTE_IDS["claude-mem"].values()))
        ipc = IPC()
        handlers = build_memory_handlers(
            targets={("p1", "n1", "claude-mem"): t},
            owner_state=lambda _: ("claude-mem", 4), queue=None, ipc=ipc,
            eligibility=lambda *_: True)
        response = call(handlers[("memory.capture", "memory:claude-mem:capture")],
            Context(), "capture", {"schema": 1, "record_id": "synthetic-id",
                "source": "hermes-session:synthetic", "facts": ["synthetic fact"],
                "embeddings": [[0.1, 0.2]], "provenance": ["a" * 64]}, provider="claude-mem")
        self.assertEqual(response["status"], 503)
        self.assertEqual(ipc.calls, [])

    def test_owner_change_revokes_enqueue_before_journaling(self):
        t = target("p1", "n1", "service-one")
        with tempfile.TemporaryDirectory() as directory:
            queue = DurableMemoryQueue(Path(directory) / "queue",
                owner_state=lambda _: ("claude-mem", 8),
                consent_issuer=lambda **_: {"consent_id":"revocable-1","signature":"signed"})
            with self.assertRaises(PermissionError):
                queue.enqueue(target=t, context=Context(), body={
                    "schema": 1, "event": "turn", "session_id": "s",
                    "user_content": "synthetic", "assistant_content": "synthetic",
                })
            self.assertIsNone(queue.claim())

    def test_owner_revocation_clears_private_payload_and_disables_consent(self):
        t = target("p1", "n1", "service-one")
        owner = {"value": ("agentmemory", 7)}
        with tempfile.TemporaryDirectory() as directory:
            queue = DurableMemoryQueue(Path(directory) / "queue",
                owner_state=lambda _: owner["value"],
                consent_issuer=lambda **_: {"consent_id":"consent-revoke","signature":"signed"})
            receipt = queue.enqueue(target=t, context=Context(), body={
                "schema": 1, "profile":"p1", "namespace":"n1", "event":"turn",
                "session_id":"synthetic-session", "user_content":"private queued text",
                "assistant_content":"private generated text"})
            job = queue.claim()
            self.assertTrue(queue.consent_active("consent-revoke"))
            self.assertEqual(queue.revoke_owner("p1", "agentmemory", 7), 1)
            self.assertFalse(queue.consent_active("consent-revoke"))
            result = queue.result(Context(), receipt)
            self.assertEqual(result["status"], "failed")
            with queue._db() as db:
                stored = db.execute("SELECT source_context,consent,event FROM jobs WHERE id=?", (receipt,)).fetchone()
            self.assertEqual(tuple(bytes(value) for value in stored), (b"", b"", b""))
            # A writer that returns after revocation must not resurrect bytes or
            # turn an already failed job back into a completed capture.
            queue.finish(job, {"too_late": True})
            self.assertEqual(queue.result(Context(), receipt)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
