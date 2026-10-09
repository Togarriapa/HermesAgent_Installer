"""Durable one-use root memory compound transitions (SK01 / SK-T01)."""
import tempfile
import unittest
import hashlib
import time
import json
import sqlite3
from pathlib import Path

from hermes_installer.authority.memory_execution import (
    MemoryCompoundExecutor,
    MemoryCompoundLedger,
    MemoryExecutionDenied,
    MemoryRecipeUnavailable,
)
from hermes_installer.memory.compound import MemoryRouteRecipe, MemoryRouteStep
from hermes_installer.memory.broker import DurableMemoryQueue
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.authority.types import (
    EffectAuthorization, HostContext, Sensitivity, canonical_digest,
)
from hermes_installer.memory.compound import canonical_json


def enrolled():
    recipe = MemoryRouteRecipe(
        approved_route_id="agentmemory-search", backend_variant="default",
        steps=(MemoryRouteStep("search", "POST", "/agentmemory/smart-search",
                              "agentmemory-search-owned-v1",
                              "agentmemory-search-result-v1", (), None),),
        request_schema_id="agentmemory-search-request-v1",
        result_schema_id="agentmemory-search-result-v1",
        scope_bindings={
            "profile_id": "profile-one", "service_generation": "svc-generation-one",
            "memory_owner_generation": 3, "backend_project_ref": "project-one",
            "backend_agent_ref": "profile-one", "backend_session_ref": None,
            "private_provider_route_ref": None,
            "credential_reference_id": "vault-ref-one",
        }, credential_reference_id="vault-ref-one", maximum_seconds=15,
        maximum_bytes=4096,
    )
    enrollment = MemoryServiceEnrollment(
        target_id="memory-agentmemory:profile-one", provider="agentmemory",
        backend_variant="default", profile_id="profile-one", principal_id="principal-one",
        service_enrollment_id="service-one", source_revision="df3d4a83b966d8d415cb9180d5a4724b07f729dc",
        service_generation="svc-generation-one", namespace_identity="namespace-one",
        literal_loopback_port=3111, fixed_route_map={"agentmemory-search": recipe},
        data_root_id="data-one", auth_reference_id="vault-ref-one",
        fixed_project_account_user_scope={"project_id": "project-one", "account_id": "account-one",
                                          "user_id": "profile-one"},
        authority_state_root_id="authority-root-one",
        memory_owner_generation=3,
        private_extraction_embedding_routes={"extract": "local-extract", "embed": "local-embed"},
        background_consent_revision="consent-one",
        limits={"request_bytes": 4096, "response_bytes": 8192, "result_limit": 10,
                "operation_timeout_seconds": 10, "whole_compound_timeout_seconds": 15},
    )
    return enrollment, recipe


def parent_effect(enrollment, route_id, body):
    action = "search" if "search" in route_id else "capture"
    capability = "memory-retrieval" if action == "search" else "memory-capture"
    operation = f"memory.{action}"
    target = f"memory:{enrollment.provider}:{action}"
    payload = canonical_json({"schema": 1, **body})
    digest = hashlib.sha256(payload).hexdigest()
    now = time.monotonic()
    context = HostContext(
        principal_id=enrollment.principal_id, profile_id=enrollment.profile_id,
        namespace_id=enrollment.namespace_identity, uid=1001,
        purpose=f"memory-{action}", intent_id="memory-intent",
        trace_id="memory-trace", sensitivity=Sensitivity.PRIVATE,
        lineage_hash=hashlib.sha256(b"source-lineage").hexdigest(),
        policy_revision="policy-one", capabilities=frozenset({capability}),
        issued_at_monotonic=now, monotonic_expires_at=now + 30,
        nonce="context-nonce", grant_id="context-grant", signature="test-signature",
        final_payload_digest=digest, operation=operation,
    )
    grant = EffectAuthorization(
        principal_id=context.principal_id, profile_id=context.profile_id,
        namespace_id=context.namespace_id, uid=context.uid, purpose=context.purpose,
        sensitivity=context.sensitivity, trace_id=context.trace_id,
        policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
        capability=capability, intent_id=context.intent_id, target=target,
        recipient=None, request_digest=digest, retry_index=0,
        issued_at_monotonic=now, monotonic_expires_at=now + 30,
        grant_id="parent-grant", nonce="parent-nonce",
        context_digest=canonical_digest({**context.claims(), "signature": context.signature}),
        signature="test-signature", final_payload_digest=digest, operation=operation,
    )
    return context, grant, payload


def admit(ledger, enrollment, recipe, body, *, consent=None):
    context, grant, payload = parent_effect(enrollment, recipe.approved_route_id,
        {"query": body.get("query", "synthetic"), "limit": body.get("limit", 1)})
    return ledger.admit(enrollment=enrollment, recipe=recipe,
        request_body=body, source_context_wire=context.to_wire(), consent_wire=consent,
        target_id=enrollment.target_id,
        recipe_sha256=canonical_digest({"recipe": recipe.approved_route_id}),
        parent_grant_id=grant.grant_id, parent_context_digest=grant.context_digest,
        parent_request_digest=hashlib.sha256(payload).hexdigest(),
        deadline_monotonic=time.monotonic() + 10, maximum_bytes=4096)


class MemoryCompoundLedgerTests(unittest.TestCase):
    def test_step_is_reserved_once_and_completion_erases_source_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = MemoryCompoundLedger(Path(directory) / "owned")
            enrollment, recipe = enrolled()
            job = admit(ledger, enrollment, recipe,
                {"query": "synthetic restart fact", "limit": 4})
            source, _, _ = ledger.begin_step(job.handle, expected_sequence=1,
                step_id="search", expected_step_id="search")
            self.assertTrue(source)
            with self.assertRaises(MemoryExecutionDenied):
                ledger.begin_step(job.handle, expected_sequence=1,
                    step_id="search", expected_step_id="search")
            complete = ledger.commit_step(job.handle, step_id="search", sequence=1,
                step_index=0, captures={}, final=True)
            self.assertEqual(complete.state, "complete")
            self.assertEqual(dict(complete.request_body), {})
            with self.assertRaises(MemoryExecutionDenied):
                ledger.begin_step(job.handle, expected_sequence=2,
                    step_id="search", expected_step_id="search")

    def test_owner_revocation_atomically_clears_active_job_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = MemoryCompoundLedger(Path(directory) / "owned")
            enrollment, recipe = enrolled()
            job = admit(ledger, enrollment, recipe,
                {"query": "private synthetic text", "limit": 2},
                consent=b'{"consent_id":"c"}')
            self.assertEqual(ledger.revoke_owner("profile-one", "agentmemory", 3), 1)
            revoked = ledger.get(job.handle)
            self.assertEqual(revoked.state, "revoked")
            self.assertEqual(dict(revoked.request_body), {})
            with self.assertRaises(MemoryExecutionDenied):
                ledger.begin_step(job.handle, expected_sequence=1,
                    step_id="search", expected_step_id="search")

    def test_queue_owner_revocation_clears_compound_rows_in_the_same_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "owned"
            queue = DurableMemoryQueue(root, owner_state=lambda _profile: ("agentmemory", 3),
                                       consent_issuer=lambda **_kwargs: None)
            ledger = MemoryCompoundLedger(root)
            enrollment, recipe = enrolled()
            job = admit(ledger, enrollment, recipe, {"query": "synthetic", "limit": 1})
            self.assertEqual(queue.path, ledger.path)
            queue.revoke_owner("profile-one", "agentmemory", 3)
            self.assertEqual(ledger.get(job.handle).state, "revoked")

    def test_interrupted_step_is_ambiguous_and_is_never_replayed_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "owned"
            ledger = MemoryCompoundLedger(root)
            enrollment, recipe = enrolled()
            job = admit(ledger, enrollment, recipe, {"query": "synthetic", "limit": 1})
            ledger.begin_step(job.handle, expected_sequence=1,
                step_id="search", expected_step_id="search")
            restarted = MemoryCompoundLedger(root)
            self.assertEqual(restarted.get(job.handle).state, "ambiguous")
            with self.assertRaises(MemoryExecutionDenied):
                restarted.begin_step(job.handle, expected_sequence=1,
                    step_id="search", expected_step_id="search")

    def test_executor_serializes_enrolled_request_and_binds_compound_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            enrollment, recipe = enrolled()
            observed = {}

            def effect(reservation_handle, canonical_connector_payload_bytes,
                       serialized_service_request_sha256, *, timeout, cancelled):
                observed.update({"reservation_handle": reservation_handle,
                    "canonical_connector_payload_bytes": canonical_connector_payload_bytes,
                    "serialized_service_request_sha256": serialized_service_request_sha256,
                    "timeout": timeout, "cancelled": cancelled})
                return 200, b'{"mode":"compact","results":[]}'

            executor = MemoryCompoundExecutor(
                MemoryCompoundLedger(Path(directory) / "owned"), effect)
            body = {"query": "private fact", "limit": 5}
            context, grant, payload = parent_effect(enrollment, recipe.approved_route_id, body)
            result = executor.execute(enrollment=enrollment, recipe=recipe,
                body=body, source_context_wire=context.to_wire(),
                parent_authorization=grant, parent_request_payload=payload)
            self.assertEqual(result["status"], "ok")
            envelope = json.loads(observed["canonical_connector_payload_bytes"])
            self.assertEqual(observed["reservation_handle"], envelope["compound_job_handle"])
            self.assertEqual(envelope["generation"], enrollment.service_generation)
            self.assertEqual(envelope["sequence"], 1)
            self.assertEqual(envelope["step_id"], "search")
            self.assertEqual(envelope["body"], body)
            self.assertEqual(len(observed["serialized_service_request_sha256"]), 64)
            self.assertGreater(observed["timeout"], 0)
            with sqlite3.connect(Path(directory) / "owned" / "memory-queue.sqlite3") as db:
                binding = db.execute("SELECT target_id,recipe_sha256,parent_grant_id,"
                    "parent_context_digest,parent_request_digest FROM compound_bindings WHERE handle=?",
                    (observed["reservation_handle"],)).fetchone()
            self.assertEqual(binding[0], enrollment.target_id)
            self.assertEqual(binding[2], grant.grant_id)
            self.assertEqual(binding[4], hashlib.sha256(payload).hexdigest())

    def test_malformed_service_result_marks_compound_ambiguous_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            enrollment, recipe = enrolled()
            called = []

            def effect(reservation_handle, _envelope, _request_digest, *, timeout, cancelled):
                called.append(reservation_handle)
                return 200, b'{"mode":"unrecognized","results":[]}'

            ledger = MemoryCompoundLedger(Path(directory) / "owned")
            executor = MemoryCompoundExecutor(ledger, effect)
            body = {"query": "private fact", "limit": 5}
            context, grant, payload = parent_effect(enrollment, recipe.approved_route_id, body)
            with self.assertRaises(MemoryRecipeUnavailable):
                executor.execute(enrollment=enrollment, recipe=recipe,
                    body=body, source_context_wire=context.to_wire(),
                    parent_authorization=grant, parent_request_payload=payload)
            self.assertEqual(len(called), 1)
            self.assertEqual(ledger.get(called[0]).state, "ambiguous")

    def test_parent_grant_must_bind_exact_memory_action_and_request(self):
        with tempfile.TemporaryDirectory() as directory:
            enrollment, recipe = enrolled()
            body = {"query": "private fact", "limit": 5}
            context, grant, payload = parent_effect(enrollment, recipe.approved_route_id, body)
            other = canonical_json({"schema": 1, "query": "changed", "limit": 5})
            executor = MemoryCompoundExecutor(MemoryCompoundLedger(Path(directory) / "owned"),
                                               lambda **_kwargs: self.fail("effect before binding"))
            with self.assertRaises(MemoryExecutionDenied):
                executor.execute(enrollment=enrollment, recipe=recipe,
                    body=body, source_context_wire=context.to_wire(),
                    parent_authorization=grant, parent_request_payload=other)


if __name__ == "__main__":
    unittest.main()
