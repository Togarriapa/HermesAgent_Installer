"""Durable one-use root memory compound transitions (SK01 / SK-T01)."""
import tempfile
import unittest
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
        memory_owner_generation=3,
        private_extraction_embedding_routes={"extract": "local-extract", "embed": "local-embed"},
        background_consent_revision="consent-one",
        limits={"request_bytes": 4096, "response_bytes": 8192, "result_limit": 10,
                "operation_timeout_seconds": 10, "whole_compound_timeout_seconds": 15},
    )
    return enrollment, recipe


class MemoryCompoundLedgerTests(unittest.TestCase):
    def test_step_is_reserved_once_and_completion_erases_source_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = MemoryCompoundLedger(Path(directory) / "owned")
            enrollment, recipe = enrolled()
            job = ledger.admit(enrollment=enrollment, recipe=recipe,
                request_body={"query": "synthetic restart fact", "limit": 4},
                source_context_wire=b'{"signature":"root-proof"}', consent_wire=None,
                deadline_monotonic=__import__("time").monotonic() + 10,
                maximum_bytes=4096)
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
            job = ledger.admit(enrollment=enrollment, recipe=recipe,
                request_body={"query": "private synthetic text", "limit": 2},
                source_context_wire=b'{"signature":"root-proof"}', consent_wire=b'{"consent_id":"c"}',
                deadline_monotonic=__import__("time").monotonic() + 10,
                maximum_bytes=4096)
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
            job = ledger.admit(enrollment=enrollment, recipe=recipe,
                request_body={"query": "synthetic", "limit": 1},
                source_context_wire=b'{"signature":"root-proof"}', consent_wire=None,
                deadline_monotonic=__import__("time").monotonic() + 10,
                maximum_bytes=4096)
            self.assertEqual(queue.path, ledger.path)
            queue.revoke_owner("profile-one", "agentmemory", 3)
            self.assertEqual(ledger.get(job.handle).state, "revoked")

    def test_interrupted_step_is_ambiguous_and_is_never_replayed_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "owned"
            ledger = MemoryCompoundLedger(root)
            enrollment, recipe = enrolled()
            job = ledger.admit(enrollment=enrollment, recipe=recipe,
                request_body={"query": "synthetic", "limit": 1},
                source_context_wire=b'{"signature":"root-proof"}', consent_wire=None,
                deadline_monotonic=__import__("time").monotonic() + 10,
                maximum_bytes=4096)
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

            def effect(**kwargs):
                observed.update(kwargs)
                return 200, b'{"mode":"compact","results":[]}'

            executor = MemoryCompoundExecutor(
                MemoryCompoundLedger(Path(directory) / "owned"), effect)
            result = executor.execute(enrollment=enrollment, recipe=recipe,
                body={"query": "private fact", "limit": 5},
                source_context_wire=b'{"signature":"root-proof"}',
                parent_authorization=object())
            self.assertEqual(result["status"], "ok")
            self.assertEqual(observed["request_path"], "/agentmemory/smart-search")
            self.assertEqual(observed["request_method"], "POST")
            self.assertEqual(observed["request_headers"], (("Content-Type", "application/json"),))
            self.assertEqual(observed["request_body"],
                b'{"agentId":"profile-one","limit":5,"project":"project-one","query":"private fact"}')
            self.assertEqual(len(observed["request_digest"]), 64)
            self.assertIn(b'"step_id":"search"', observed["compound_envelope"])
            self.assertIsNotNone(observed["parent_authorization"])

    def test_malformed_service_result_marks_compound_ambiguous_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            enrollment, recipe = enrolled()
            called = []

            def effect(**kwargs):
                called.append(kwargs["job_handle"])
                return 200, b'{"mode":"unrecognized","results":[]}'

            ledger = MemoryCompoundLedger(Path(directory) / "owned")
            executor = MemoryCompoundExecutor(ledger, effect)
            with self.assertRaises(MemoryRecipeUnavailable):
                executor.execute(enrollment=enrollment, recipe=recipe,
                    body={"query": "private fact", "limit": 5},
                    source_context_wire=b'{"signature":"root-proof"}',
                    parent_authorization=object())
            self.assertEqual(len(called), 1)
            self.assertEqual(ledger.get(called[0]).state, "ambiguous")


if __name__ == "__main__":
    unittest.main()
