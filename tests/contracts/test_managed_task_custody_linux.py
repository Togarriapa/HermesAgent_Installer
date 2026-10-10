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
from hermes_installer.managed_process_custodian import process_start_target
from hermes_installer.registry.resource_jobs import RootAdmittedTask


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
        package = fixture._native_package_fixture()
        binding = package.binding
        script = self._loader_prefix(binding) + script
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
        recipes["hermes-resource-profile-task-v1"] = recipe
        profile = replace(fixture.profile, child_artifact_refs=children,
                          native_package=binding,
                          operation_recipes=recipes)
        fixture.profile = profile
        fixture.handler.profiles[profile.profile_id] = profile
        fixture.handler.native_package_resolver = lambda profile_id, generation: (
            package if profile_id == profile.profile_id and generation == profile.generation else None)
        from hermes_installer.authority.native_custody_proof import (
            NativeLoaderSelection, RootNativeLoaderObservationStore,
        )

        def active_loader_selection(owned_handle):
            return NativeLoaderSelection(
                process_id=owned_handle.process_id, package_id=binding.package_id,
                profile_id=binding.profile_id, generation=binding.generation,
                compiled_closure_sha256=binding.compiled_closure_sha256,
                entrypoint_sha256=binding.entrypoint_sha256,
                resolver_sha256=binding.resolver_sha256,
                service_generation_digest="d" * 64,
                loader_role_artifact_id=binding.entrypoint_artifact_id,
                loader_role_sha256=binding.entrypoint_sha256,
                registered_action_ids=("ci-native-action",),
            )

        store = RootNativeLoaderObservationStore(
            fixture.handler, active_loader_selection, source_target_selector=lambda *_args: None)
        previous_store = fixture.handler.native_loader_observation_store
        if previous_store is not None:
            # The cancellation/expiry case admits two sequential tasks through
            # one fixture manager. The earlier task is terminal before this
            # helper runs again, so retire its loader observer before replacing
            # the selected package/generation closure for the next task.
            previous_store.close()
            fixture.handler.native_loader_observation_store = None
        fixture.handler.set_native_loader_observation_store(store)

        task_payload = json.dumps({"prompt": prompt}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        exact_stdin = prompt.encode("utf-8")
        now = time.monotonic()
        admission_id = "admission-" + fixture.token[:16]
        admission_handle = "handle-" + fixture.token[:25]
        task = RootAdmittedTask(
            schema=1, admission_id=admission_id, job_id="job-" + fixture.token[:16],
            node_id="node-" + suffix, backend_enrollment_id="backend-" + fixture.token[:16],
            resource_generation="resource-gen-" + fixture.token[:16],
            native_package_id="package-" + fixture.token[:16],
            native_package_generation=profile.generation,
            process_enrollment_id=profile.enrollment_id,
            process_generation=profile.generation,
            operation_id="hermes-resource-profile-task-v1",
            task_body_recipe_id="task-" + suffix,
            task_request_schema_id="prompt-v1", task_payload_bytes=task_payload,
            task_payload_sha256=hashlib.sha256(task_payload).hexdigest(),
            parent_closure_digest="a" * 64, deadline_monotonic=now + 20,
            source_context_handle="source-context-" + fixture.token[:16],
            stdin_sha256=hashlib.sha256(exact_stdin).hexdigest(),
            stdin_size_bytes=len(exact_stdin))
        selection = json.dumps({"schema": 1, "enrollment_id": profile.enrollment_id,
            "generation": profile.generation, "operation_id": task.operation_id,
            "parameters": {}, "admission_handle": admission_handle,
            "node_id": task.node_id, "task_payload_sha256": task.task_payload_sha256,
            "stdin_sha256": task.stdin_sha256, "stdin_size_bytes": task.stdin_size_bytes},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("ascii")
        final_digest = canonical_digest(selection)
        context = SimpleNamespace(
            profile_id=profile.profile_id, enrollment_id=profile.enrollment_id,
            generation=profile.generation, operation="process.start",
            principal_id="resource-principal-" + fixture.token[:12],
            namespace_id="resource-namespace-" + fixture.token[:12],
            trace_id="resource-trace-" + fixture.token[:12], intent_id="resource-intent-" + fixture.token[:12],
            purpose="resource-task", sensitivity="private", lineage_hash="b" * 64,
            policy_revision="policy-" + fixture.token[:12], uid=fixture.uid,
            final_payload_digest=final_digest)
        authorization = SimpleNamespace(
            profile_id=profile.profile_id, enrollment_id=profile.enrollment_id,
            generation=profile.generation, operation="process.start",
            principal_id=context.principal_id, namespace_id=context.namespace_id,
            trace_id=context.trace_id, intent_id=context.intent_id,
            purpose=context.purpose, sensitivity=context.sensitivity,
            lineage_hash=context.lineage_hash, policy_revision=context.policy_revision,
            uid=fixture.uid, capability="hermes-profile-invoke", target=process_start_target(profile),
            request_digest=final_digest, final_payload_digest=final_digest,
            monotonic_expires_at=now + 20)
        admission_live = {"value": True}
        fixture.handler.task_admission_current = lambda candidate, launch_payload: (
            admission_live["value"] and candidate.admission_id == task.admission_id
            and candidate.process_generation == fixture.handler.profiles[profile.profile_id].generation
            and json.loads(launch_payload.decode("ascii"))["admission_handle"] == admission_handle)
        parent_pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            handle = fixture.handler.start_selected_task(
                profile, context, authorization, selection, task_handle=task,
                exact_stdin=exact_stdin,
                expected_stdin_sha256=expected_hash_override or task.stdin_sha256,
                peer_pid=os.getpid(), peer_pidfd=parent_pidfd, timeout=10,
                cancelled=lambda: False)
        except BaseException:
            os.close(parent_pidfd)
            raise
        return handle, task, exact_stdin, admission_live, parent_pidfd

    @staticmethod
    def _loader_prefix(binding) -> str:
        return (
            "import json,socket,struct\n"
            "_sock=socket.socket(fileno=3)\n"
            "_nonce=b''\n"
            "while len(_nonce)<43:\n"
            "    _part=_sock.recv(43-len(_nonce))\n"
            "    if not _part: raise SystemExit(91)\n"
            "    _nonce+=_part\n"
            f"_package={binding.package_id!r}\n"
            f"_generation={binding.generation!r}\n"
            f"_entrypoint={binding.entrypoint_sha256!r}\n"
            f"_resolver={binding.resolver_sha256!r}\n"
            "for _seq,_phase in enumerate(('entrypoint-imported','actions-registered','ready')):\n"
            "    _actions=[] if _seq==0 else ['ci-native-action']\n"
            "    _record={'schema':1,'launch_nonce':_nonce.decode('ascii'),'sequence':_seq,"
            "'phase':_phase,'package_id':_package,'generation':_generation,"
            "'entrypoint_sha256':_entrypoint,'resolver_sha256':_resolver,"
            "'registered_action_ids':_actions}\n"
            "    _body=json.dumps(_record,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')\n"
            "    _sock.sendall(struct.pack('!I',len(_body))+_body)\n"
            "_sock.close()\n"
        )

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
            process_lease = fixture.handler.resolve_managed_task_process_handle(handle)
            self.assertIsNotNone(process_lease,
                "active task handle did not resolve to its root-registered process")
            self.assertEqual(process_lease.process_id, handle.process_id)
            self.assertEqual(process_lease.generation, handle.generation)
            self.assertEqual(process_lease.uid, fixture.uid)
            self.assertEqual(process_lease.pid, fixture.handler._handles[handle.process_id].pid)
            self.assertNotEqual(process_lease.pidfd,
                fixture.handler._handles[handle.process_id].child_pidfd)
            process_lease.close()
            self.assertIsNone(fixture.handler.resolve_managed_task_process_handle(
                type(handle)(handle.handle_id, "stale-generation", handle.process_id)))
            terminal = fixture.handler.wait_owned_task_terminal(
                handle, deadline_monotonic=task.deadline_monotonic, cancelled=lambda: False)
        finally:
            os.close(parent_fd)
        self.assertEqual(query_file.read_bytes(), exact)
        self.assertEqual(terminal.exit_code, 0)
        self.assertEqual(terminal.schema, 1)
        self.assertEqual(terminal.state, "completed")
        self.assertEqual(terminal.task_handle_id, handle.handle_id)
        self.assertEqual(handle.process_id, terminal.process_id)
        self.assertTrue(terminal.native_loader_ready_event_id)
        self.assertEqual(terminal.admission_handle_id, "handle-" + self.fixture.token[:25])
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
                handle, deadline_monotonic=task.deadline_monotonic, cancelled=lambda: True)
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


class RootTaskNativeFixturePreflightTests(unittest.TestCase):
    def test_fixture_rejects_noncomposed_runtime_before_systemd_or_actor_probe(self) -> None:
        from task_native_fixture import (
            RootInstalledTaskRuntime,
            TaskNativeFixtureUnavailable,
        )

        with self.assertRaisesRegex(TaskNativeFixtureUnavailable, "composed RootAuthorityRuntime"):
            RootInstalledTaskRuntime.bind_current_main_pid(object(), unit_id="fixture.service")


class RootTaskQualificationRecipeTests(unittest.TestCase):
    def test_recipe_is_finite_and_request_schema_is_bounded(self) -> None:
        from hermes_installer.authority.qualification_resource_cron_recipe import (
            RECIPE,
            RECIPE_ID,
            SCHEMA_ID,
            SUITE_ID,
        )
        from hermes_installer.authority.qualification_resource_cron_schema import (
            MAX_PROMPT_BYTES,
            canonical_request,
        )

        self.assertEqual(SUITE_ID, "resource-cron-task-v1")
        self.assertEqual(RECIPE["recipe_id"], RECIPE_ID)
        self.assertEqual(RECIPE["schema_id"], SCHEMA_ID)
        self.assertEqual(RECIPE["additional_metered_budget"], 0)
        self.assertNotIn("path", RECIPE)
        self.assertNotIn("command", RECIPE)
        self.assertEqual(canonical_request("bounded input"),
                         b'{"prompt":"bounded input","schema":1}')
        with self.assertRaises(ValueError):
            canonical_request("x" * (MAX_PROMPT_BYTES + 1))

    def test_public_selection_and_result_dtos_cannot_be_forged(self) -> None:
        from hermes_installer.authority.installed_qualification import (
            RootInstalledQualificationResult,
            RootOwnedQualificationFixtureSelection,
        )

        with self.assertRaisesRegex(TypeError, "only be minted by their owning registry"):
            RootOwnedQualificationFixtureSelection(
                schema=1, selection_handle="x" * 32, suite_id="resource-cron-task-v1",
                fixture_recipe_artifact_id="fixture-recipe", fixture_recipe_sha256="0" * 64,
                fixture_schema_artifact_id="fixture-schema", fixture_schema_sha256="1" * 64,
                release_deployment_receipt_sha256="2" * 64,
                root_actor_observation_handle="actor", fixture_root_observation_handle="root",
                fixture_environment_observation_handle="environment",
                controller_unit_observation_handle="unit", fixture_generation_id="generation",
                fixture_namespace_id="namespace", fixture_profile_id="profile",
                fixture_principal_id="principal", fixture_payload_sha256="3" * 64,
                issued_monotonic=1.0, expires_monotonic=2.0,
            )
        with self.assertRaisesRegex(TypeError, "only be returned by the installed registry"):
            RootInstalledQualificationResult(
                schema=1, suite_id="resource-cron-task-v1", fixture_selection_handle=None,
                fixture_generation_id=None, release_deployment_receipt_sha256="0" * 64,
                controller_observation_handle=None, parent_receipt_handles=(),
                terminal_receipt_handle=None, cleanup_receipt_handle=None,
                evidence_sha256=None, status="passed",
            )
