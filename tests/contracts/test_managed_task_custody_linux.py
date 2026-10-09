"""Actual Linux proof for root-admitted stdin-once task custody."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace

from hermes_installer.authority.types import canonical_digest
from hermes_installer.managed_process_custodian import (
    RootAdmittedTask,
)


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "pidfd_open"),
                     "requires isolated Linux root/systemd CI")
class ManagedTaskCustodyLinuxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        module = importlib.import_module("tests.contracts.test_managed_process_custody_linux")
        cls.fixture_type = module.ManagedProcessRootAuthorityIntegrationTests
        cls.fixture_type.setUpClass()

    def setUp(self) -> None:
        self.fixture = self.fixture_type(
            "test_authority_rpc_enforces_kernel_boundaries_and_stubborn_descendant_cleanup")
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _admit_and_start(self, *, suffix: str, script: str, prompt: str,
                         expected_hash_override: str | None = None):
        fixture = self.fixture
        store_id, digest, _ = fixture._enroll_script("task-" + suffix, script)
        task_script = fixture.script_root / ("task-" + suffix + ".py")
        original_resolver = fixture.handler.artifact_resolver
        fixture.handler.artifact_resolver = lambda selected_id, selected_digest: (
            task_script if selected_id == store_id and selected_digest == digest
            else original_resolver(selected_id, selected_digest))
        children = dict(fixture.profile.child_artifact_refs or {})
        children[store_id] = digest
        recipe = fixture._operation_recipe(store_id, digest, "task-" + suffix)
        recipe["stdin_mode"] = "bounded-typed-bytes"
        recipes = dict(fixture.profile.operation_recipes or {})
        recipes["task-" + suffix] = recipe
        profile = replace(fixture.profile, child_artifact_refs=children,
                          operation_recipes=recipes)
        fixture.profile = profile
        fixture.handler.profiles[profile.profile_id] = profile

        task_payload = json.dumps({"prompt": prompt}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii")
        exact_stdin = prompt.encode("utf-8")
        now = time.monotonic()
        task = RootAdmittedTask(
            handle_id="admission-" + fixture.token[:16], job_id="job-" + fixture.token[:16],
            node_id="node-" + suffix, child_admission_id="child-" + fixture.token[:16],
            attempt_index=0, backend_enrollment_id="backend-" + fixture.token[:16],
            resource_generation="resource-gen-" + fixture.token[:16],
            profile_id=profile.profile_id, profile_generation=profile.generation,
            native_package_id="package-" + fixture.token[:16],
            native_package_generation=profile.generation,
            process_enrollment_id=profile.enrollment_id,
            process_generation=profile.generation,
            operation_id="resource.bundle.node.run",
            child_target_id="resource:fixture:task:" + fixture.token[:16],
            child_capability="hermes-resource-runtime",
            task_body_recipe_id="task-" + suffix,
            task_request_schema_id="prompt-v1", task_payload=task_payload,
            task_payload_sha256=hashlib.sha256(task_payload).hexdigest(),
            parent_closure_digest="a" * 64, expires_monotonic=now + 20,
            stdin_sha256=hashlib.sha256(exact_stdin).hexdigest(),
            stdin_size_bytes=len(exact_stdin))
        selection = json.dumps({"schema": 1, "enrollment_id": profile.enrollment_id,
            "generation": profile.generation, "operation_id": task.task_body_recipe_id,
            "parameters": {}}, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("ascii")
        final_digest = canonical_digest(selection)
        context = SimpleNamespace(
            profile_id=profile.profile_id, enrollment_id=profile.enrollment_id,
            generation=profile.generation, operation=task.operation_id,
            principal_id="resource-principal-" + fixture.token[:12],
            namespace_id="resource-namespace-" + fixture.token[:12],
            trace_id="resource-trace-" + fixture.token[:12], intent_id="resource-intent-" + fixture.token[:12],
            purpose="resource-task", sensitivity="private", lineage_hash="b" * 64,
            policy_revision="policy-" + fixture.token[:12], uid=fixture.uid,
            final_payload_digest=final_digest)
        authorization = SimpleNamespace(
            profile_id=profile.profile_id, enrollment_id=profile.enrollment_id,
            generation=profile.generation, operation=task.operation_id,
            principal_id=context.principal_id, namespace_id=context.namespace_id,
            trace_id=context.trace_id, intent_id=context.intent_id,
            purpose=context.purpose, sensitivity=context.sensitivity,
            lineage_hash=context.lineage_hash, policy_revision=context.policy_revision,
            uid=fixture.uid, capability=task.child_capability, target=task.child_target_id,
            request_digest=final_digest, final_payload_digest=final_digest,
            monotonic_expires_at=now + 20)
        admission_live = {"value": True}
        fixture.handler.task_admission_current = lambda candidate: (
            admission_live["value"] and candidate.handle_id == task.handle_id
            and candidate.profile_generation == fixture.handler.profiles[profile.profile_id].generation)
        parent_pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            handle = fixture.handler.start_selected_task(
                profile, context, authorization, selection, task_admission=task,
                exact_stdin=exact_stdin,
                expected_stdin_sha256=expected_hash_override or task.stdin_sha256,
                peer_pid=os.getpid(), peer_pidfd=parent_pidfd, timeout=10,
                cancelled=lambda: False)
        except BaseException:
            os.close(parent_pidfd)
            raise
        return handle, task, exact_stdin, admission_live, parent_pidfd

    def test_prompt_is_written_once_eof_observed_and_terminal_cleanup_is_proven(self) -> None:
        fixture = self.fixture
        prompt = "one frame, unicode: café\nwithout trailing newline"
        query_file = fixture.work_root / "ci" / "task-query.txt"
        script = (
            "#!/usr/bin/python3\nimport json,pathlib,sys\n"
            "data=sys.stdin.buffer.read()\n"
            f"pathlib.Path({str(query_file)!r}).write_bytes(data)\n"
            "print(json.dumps({'bytes':len(data),'sha256':__import__('hashlib').sha256(data).hexdigest()},sort_keys=True),flush=True)\n"
        )
        handle, task, exact, _, parent_fd = self._admit_and_start(
            suffix="positive", script=script, prompt=prompt)
        try:
            terminal = fixture.handler.wait_owned_task_terminal(
                handle, deadline_monotonic=task.expires_monotonic, cancelled=lambda: False)
        finally:
            os.close(parent_fd)
        self.assertEqual(query_file.read_bytes(), exact)
        self.assertEqual(terminal.exit_code, 0)
        self.assertEqual(terminal.schema, 1)
        self.assertEqual(terminal.state, "completed")
        self.assertEqual(terminal.task_handle_id, handle.handle_id)
        self.assertEqual(terminal.parent_closure_digest, "a" * 64)
        self.assertEqual(terminal.stdout_size_bytes, len(terminal.stdout))
        self.assertEqual(terminal.stderr_size_bytes, len(terminal.stderr))
        self.assertTrue(terminal.terminal_receipt_id)
        self.assertFalse(terminal.timed_out)
        self.assertFalse(terminal.cancelled)
        self.assertTrue(terminal.output_complete)
        self.assertTrue(terminal.cleanup_verified)
        self.assertTrue(terminal.cgroup_empty and terminal.main_pidfd_gone)
        self.assertTrue(terminal.descendants_gone and terminal.launcher_reaped)
        observation = json.loads(terminal.stdout.decode("utf-8").splitlines()[-1])
        self.assertEqual(observation, {"bytes": len(exact), "sha256": hashlib.sha256(exact).hexdigest()})

    def test_cancel_and_expiry_stop_owned_task_and_prove_cleanup(self) -> None:
        script = ("#!/usr/bin/python3\nimport sys,time\n"
                  "sys.stdin.buffer.read()\nprint('received',flush=True)\ntime.sleep(30)\n")
        handle, task, _, _, parent_fd = self._admit_and_start(
            suffix="cancel", script=script, prompt="cancel me")
        try:
            cancelled = self.fixture.handler.wait_owned_task_terminal(
                handle, deadline_monotonic=task.expires_monotonic, cancelled=lambda: True)
        finally:
            os.close(parent_fd)
        self.assertTrue(cancelled.cancelled)
        self.assertEqual(cancelled.state, "cancelled")
        self.assertTrue(cancelled.cleanup_verified)
        self.assertTrue(cancelled.cgroup_empty and cancelled.main_pidfd_gone and cancelled.launcher_reaped)

        handle, task, _, _, parent_fd = self._admit_and_start(
            suffix="expiry", script=script, prompt="expire me")
        try:
            expired = self.fixture.handler.wait_owned_task_terminal(
                handle, deadline_monotonic=time.monotonic() - 0.01, cancelled=lambda: False)
        finally:
            os.close(parent_fd)
        self.assertTrue(expired.timed_out)
        self.assertEqual(expired.state, "failed")
        self.assertTrue(expired.cleanup_verified)
        self.assertTrue(expired.cgroup_empty and expired.main_pidfd_gone and expired.launcher_reaped)

    def test_mismatched_prompt_digest_is_denied_before_any_process_starts(self) -> None:
        fixture = self.fixture
        with self.assertRaises(PermissionError):
            self._admit_and_start(suffix="bad-hash", script="import sys; sys.stdin.read()\n",
                prompt="digest mismatch", expected_hash_override="0" * 64)
        self.assertFalse(fixture.handler._handles)
        self.assertFalse(fixture.handler._starting)
