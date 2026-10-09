"""Effect and failure contracts for the root memory broker."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from hermes_installer.memory.broker import (
    BrokerDenied, DurableMemoryQueue, MemoryTarget, build_memory_handlers,
    canonical, ROUTE_IDS, build_memory_runtime,
)


class Context:
    def __init__(self, profile="p1", namespace="n1"):
        self.profile_id = profile
        self.namespace_id = namespace
        self.lineage_hash = "a" * 64
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
    def __init__(self, profile, namespace, target, digest):
        self.profile_id, self.namespace_id = profile, namespace
        self.target, self.request_digest = target, digest


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
    grant = Grant(context.profile_id, context.namespace_id,
                  "memory:" + provider + ":" + action,
                  digest_override or hashlib.sha256(raw).hexdigest())
    return handler(context=context, authorization=grant, payload=raw, timeout=1.0,
                   peer_pid=123, cancelled=lambda: False)


class MemoryBrokerTests(unittest.TestCase):
    def test_fixed_handler_resolves_distinct_service_from_host_context(self):
        t1, t2 = target("p1", "n1", "service-one"), target("p2", "n2", "service-two")
        ipc = IPC()
        owner = lambda profile: (None, 0)
        handlers = build_memory_handlers(
            targets={("p1", "n1", "agentmemory"): t1, ("p2", "n2", "agentmemory"): t2},
            owner_state=owner, queue=None, ipc=ipc)
        handler = handlers[("memory.doctor", "memory:agentmemory:doctor")]
        first = call(handler, Context(), "doctor", {"schema": 1})
        second = call(handler, Context("p2", "n2"), "doctor", {"schema": 1})
        self.assertEqual(first["status"], 200)
        self.assertEqual(second["status"], 200)
        self.assertEqual([item["service_id"] for item in ipc.calls], ["service-one", "service-two"])
        self.assertEqual([item["service_generation"] for item in ipc.calls], [1, 1])
        self.assertEqual([item["route_id"] for item in ipc.calls],
                         ["memory.agentmemory.livez.v1"] * 2)
        self.assertEqual(ipc.calls[0]["context"].profile_id, "p1")
        self.assertEqual(ipc.calls[0]["authorization"].target, "memory:agentmemory:doctor")
        self.assertEqual(ipc.calls[0]["session_id"], "trace-one")
        self.assertGreater(ipc.calls[0]["deadline_monotonic"], 0)
        self.assertNotIn("fixed_route", ipc.calls[0])

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

    def test_missing_signed_session_id_denied_before_connector_bytes(self):
        t = target("p1", "n1", "service-one")
        ipc = IPC()
        handlers = build_memory_handlers(
            targets={("p1","n1","agentmemory"):t},
            owner_state=lambda _: (None,0), queue=None, ipc=ipc)
        context = Context()
        context.trace_id = None
        result = call(handlers[("memory.doctor","memory:agentmemory:doctor")],
                      context, "doctor", {"schema":1})
        self.assertEqual(result["status"], 403)
        self.assertEqual(ipc.calls, [])

    def test_unenrolled_opaque_route_denied_before_connector_bytes(self):
        t = MemoryTarget("agentmemory", "p1", "n1", "service-one",
            "df3d4a83b966d8d415cb9180d5a4724b07f729dc", 1, "root-data-p1",
            approved_route_ids=frozenset())
        ipc = IPC()
        handlers = build_memory_handlers(
            targets={("p1","n1","agentmemory"):t},
            owner_state=lambda _: (None,0), queue=None, ipc=ipc)
        result = call(handlers[("memory.doctor","memory:agentmemory:doctor")],
                      Context(), "doctor", {"schema":1})
        self.assertEqual(result["status"], 403)
        self.assertEqual(ipc.calls, [])

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


    def test_root_runtime_binds_typed_consent_to_current_owner_epoch(self):
        class SignedConsent:
            def to_wire(self):
                return {"consent_id":"runtime-consent","signature":"root-signed"}
        class Authority:
            def create_background_consent(self, **_):
                return SignedConsent()
            def perform_memory_effect(self, **_):
                raise AssertionError("runtime must not start a background worker")
        t = target("p1", "n1", "service-one")
        with tempfile.TemporaryDirectory() as directory:
            runtime = build_memory_runtime({("p1","n1","agentmemory"):t},
                Authority(), root_data_dir=Path(directory)/"runtime")
            self.assertTrue(runtime["consent_ready"])
            self.assertTrue(callable(runtime["consent_active"]))
            self.assertIsNone(runtime["ipc"])
            self.assertEqual(runtime["engines"], {})
            runtime["owner_ledger"].set_owner("p1", "agentmemory")
            context = Context()
            receipt = runtime["queue"].enqueue(target=t, context=context, body={
                "schema":1,"profile":"p1","namespace":"n1","event":"turn",
                "session_id":"synthetic","user_content":"synthetic source",
                "assistant_content":"synthetic reply"})
            self.assertTrue(runtime["consent_active"]("runtime-consent"))
            runtime["owner_ledger"].set_owner("p1", None)
            self.assertFalse(runtime["consent_active"]("runtime-consent"))
            self.assertEqual(runtime["queue"].revoke_owner("p1","agentmemory",1),1)
            self.assertFalse(runtime["consent_active"]("runtime-consent"))
            self.assertEqual(runtime["queue"].result(context,receipt)["status"],"failed")

    def test_pinned_provider_routes_and_payloads_match_upstream_contracts(self):
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
        self.assertEqual(response["status"], 200)
        self.assertEqual(ipc.calls[0]["route_id"], "memory.claude-mem.create.v1")
        self.assertNotIn("fixed_route", ipc.calls[0])
        body = json.loads(ipc.calls[0]["payload"])
        self.assertEqual(body["projectId"], "n1")
        self.assertEqual(body["kind"], "manual")
        self.assertEqual(body["facts"], ["synthetic fact"])
        self.assertEqual(body["metadata"]["hermes_lineage"], "a" * 64)

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
