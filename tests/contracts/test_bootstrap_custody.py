from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.bootstrap_custody import BootstrapCustody


class BootstrapCustodyContractTests(unittest.TestCase):
    def test_artifact_fetch_uses_pinned_id_digest_and_one_use_grant(self):
        content = b"pinned artifact fixture"
        digest = hashlib.sha256(content).hexdigest()

        class Client:
            def __init__(self):
                self.calls = []

            def context(self, **kwargs):
                self.calls.append(("context", kwargs))
                return SimpleNamespace(profile_id="installer-profile")

            def authorize_effect(self, context, **kwargs):
                self.calls.append(("authorize", kwargs))
                return "one-use-grant"

            def fetch_artifact(self, grant, **kwargs):
                self.calls.append(("fetch", grant, kwargs))
                body = json.dumps({"artifact_id": kwargs["artifact_id"],
                    "version": "1", "sha256": kwargs["sha256"],
                    "size_bytes": len(content),
                    "store_id": f"artifact:{kwargs['artifact_id']}:{kwargs['sha256']}"}).encode()
                return SimpleNamespace(status=200, body=body, receipt_id="artifact-receipt")

        client = Client()
        cancelled = lambda: False
        store_id, receipt = BootstrapCustody(client).fetch_artifact(
            artifact_id="hermes-installer-fixture", sha256=digest, max_bytes=1024,
            cancelled=cancelled)
        self.assertEqual(store_id, f"artifact:hermes-installer-fixture:{digest}")
        self.assertEqual(receipt, "artifact-receipt")
        context_call = next(call for call in client.calls if call[0] == "context")
        self.assertEqual(context_call[1]["purpose"], "hermes-bootstrap")
        self.assertEqual(context_call[1]["operation"], "artifact.fetch")
        grant_call = next(call for call in client.calls if call[0] == "authorize")
        self.assertEqual(grant_call[1]["capability"], "installer-bootstrap")
        self.assertEqual(grant_call[1]["target"], f"artifact:hermes-installer-fixture:{digest}")
        request = json.dumps({"schema": 1, "artifact_id": "hermes-installer-fixture",
            "sha256": digest, "max_bytes": 1024}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(grant_call[1]["request_digest"], hashlib.sha256(request).hexdigest())
        fetch_call = next(call for call in client.calls if call[0] == "fetch")
        self.assertEqual(fetch_call[1], "one-use-grant")
        self.assertIs(fetch_call[2]["cancelled"], cancelled)

    def test_root_selected_recipe_uses_opaque_handle_controls_and_verified_stop(self):
        class Client:
            def __init__(self):
                self.selected = []
                self.controls = []
                self.reads = {"stdout": False, "stderr": False}

            def start_enrolled_process_operation(self, **kwargs):
                self.selected.append(kwargs)
                receipt = {"process_id": "a" * 32, "generation": "g-1", "uid": 1234}
                return SimpleNamespace(status=200, body=json.dumps(receipt).encode(),
                                       receipt_id="start-receipt")

            def process_control_operation(self, operation, *, process_id, generation,
                                          fields=None, timeout=5.0, cancelled=None):
                self.controls.append((operation, process_id, generation, fields or {}))
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 0})
                if operation == "process.read":
                    stream = fields["stream"]
                    data = b"ok\n" if stream == "stdout" else b""
                    self.reads[stream] = True
                    return SimpleNamespace(state="exited", result={
                        "data_bytes": base64.b64encode(data).decode(), "eof": True,
                        "redacted": False})
                if operation == "process.stop":
                    return SimpleNamespace(state="stopped", result={
                        "closed": True, "reap_state": "complete"})
                raise AssertionError(operation)

        client = Client()
        result = BootstrapCustody(client).run_selected_operation(
            enrollment_id="enrollment-a", generation="generation-a",
            operation_id="hermes-agent-health-v1", timeout=5)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, b"ok\n")
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(client.selected[0]["parameters"], {})
        self.assertEqual(client.selected[0]["operation_id"], "hermes-agent-health-v1")
        self.assertEqual([call[0] for call in client.controls], [
            "process.status", "process.read", "process.read", "process.stop"])
        self.assertTrue(all(call[1] == "a" * 32 and call[2] == "g-1"
                            for call in client.controls))
        self.assertEqual(client.controls[-1][3], {"reason": "shutdown", "grace_seconds": 5})

    def test_physical_path_launch_is_rejected(self):
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        with self.assertRaisesRegex(BootstrapCustodyError, "Physical-path process launch is disabled"):
            BootstrapCustody(object()).run_process(executable="/bin/bash", argv=["/bin/bash", "-c", "id"])

    def test_stop_without_root_cleanup_receipt_does_not_report_success(self):
        class Client:
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200,
                    body=json.dumps({"process_id": "b" * 32, "generation": "g-2", "uid": 1234}).encode(),
                    receipt_id="start-receipt")
            def process_control_operation(self, operation, **kwargs):
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 0})
                if operation == "process.read":
                    return SimpleNamespace(state="exited", result={"data_bytes": "", "eof": True})
                return SimpleNamespace(state="stopped", result={"closed": False, "reap_state": "unverified"})
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        with self.assertRaises(BootstrapCustodyError):
            BootstrapCustody(Client()).run_selected_operation(
                enrollment_id="enrollment-a", generation="generation-a",
                operation_id="hermes-agent-stage-v1", timeout=5)

    def test_selected_operation_output_overflow_stops_owned_handle(self):
        class Client:
            stopped = False
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200,
                    body=json.dumps({"process_id": "c" * 32, "generation": "g-3", "uid": 1234}).encode(),
                    receipt_id="start-receipt")
            def process_control_operation(self, operation, **kwargs):
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 0})
                if operation == "process.read":
                    return SimpleNamespace(state="exited",
                        result={"data_bytes": base64.b64encode(b"xx").decode(), "eof": True})
                self.stopped = True
                return SimpleNamespace(state="stopped", result={
                    "closed": True, "reap_state": "complete"})
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        client = Client()
        with self.assertRaises(BootstrapCustodyError) as raised:
            BootstrapCustody(client).run_selected_operation(
                enrollment_id="enrollment-a", generation="generation-a", stdout_return_limit=1,
                operation_id="hermes-agent-stage-v1", timeout=5, output_limit=1)
        self.assertIs(raised.exception.cleanup_verified, True)
        self.assertTrue(client.stopped)

    def test_cancelled_control_still_runs_uncancelled_cleanup(self):
        class Client:
            stopped = False
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200,
                    body=json.dumps({"process_id": "d" * 32, "generation": "g-4", "uid": 1234}).encode(),
                    receipt_id="start-receipt")
            def process_control_operation(self, operation, *, cancelled=None, **kwargs):
                if operation == "process.status":
                    if cancelled and cancelled():
                        raise RuntimeError("cancelled")
                if operation == "process.stop":
                    self.stopped = True
                    return SimpleNamespace(state="stopped", result={
                        "closed": True, "reap_state": "complete"})
                raise AssertionError(operation)
        client = Client()
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        with self.assertRaises(BootstrapCustodyError) as raised:
            BootstrapCustody(client).run_selected_operation(
                enrollment_id="enrollment-a", generation="generation-a",
                operation_id="hermes-agent-health-v1", timeout=5,
                cancelled=lambda: True)
        self.assertIs(raised.exception.cleanup_verified, True)
        self.assertTrue(client.stopped)


if __name__ == "__main__":
    unittest.main()

class RootSelectedHermesOperationsTests(unittest.TestCase):
    def receipt(self, *, state="committed", enrollment_ids=("service-enrollment",)):
        from hermes_installer.authority.bootstrap_enrollment import EnrollmentReceipt
        import time
        return EnrollmentReceipt(1, "transaction", "provision-receipt", "generation-7",
            "a" * 64, None, state, tuple(enrollment_ids), time.monotonic(), time.monotonic() + 60)

    def test_stage_recipe_is_fixed_and_generation_bound(self):
        from hermes_installer.bootstrap_custody import RootSelectedHermesOperations

        class Client:
            def __init__(self):
                self.started = []
                self.counter = 0
            def start_enrolled_process_operation(self, **kwargs):
                self.counter += 1
                self.started.append(kwargs)
                return SimpleNamespace(status=200, body=json.dumps({
                    "process_id": f"{self.counter:032x}", "generation": "process-gen",
                    "uid": 1234}).encode(), receipt_id=f"start-{self.counter}")
            def process_control_operation(self, operation, **kwargs):
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 0})
                if operation == "process.read":
                    return SimpleNamespace(state="exited", result={
                        "data_bytes": "", "eof": True})
                if operation == "process.stop":
                    return SimpleNamespace(state="stopped", result={
                        "closed": True, "reap_state": "complete"})
                raise AssertionError(operation)

        client = Client()
        operations = RootSelectedHermesOperations(BootstrapCustody(client), self.receipt())
        stage = operations.stage(timeout=10)
        self.assertTrue(stage.operation_completed)
        self.assertEqual([item["operation_id"] for item in client.started], [
            "hermes-agent-stage-v1"])
        self.assertTrue(all(item["parameters"] == {} for item in client.started))
        self.assertTrue(all(item["generation"] == "generation-7" for item in client.started))
        self.assertEqual(stage.generation_digest, "a" * 64)

    def test_prepared_enrollment_and_failed_stage_cannot_run_health(self):
        from hermes_installer.bootstrap_custody import (
            BootstrapCustodyError, RootSelectedHermesOperations)
        with self.assertRaises(BootstrapCustodyError):
            RootSelectedHermesOperations(BootstrapCustody(object()), self.receipt(state="prepared", enrollment_ids=()))

        class FailedClient:
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200, body=json.dumps({
                    "process_id": "f" * 32, "generation": "process-gen", "uid": 1234}).encode(),
                    receipt_id="start-failed")
            def process_control_operation(self, operation, **kwargs):
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 1})
                if operation == "process.read":
                    return SimpleNamespace(state="exited", result={"data_bytes": "", "eof": True})
                if operation == "process.stop":
                    return SimpleNamespace(state="stopped", result={"closed": True, "reap_state": "complete"})
                raise AssertionError(operation)
        operations = RootSelectedHermesOperations(BootstrapCustody(FailedClient()), self.receipt())
        stage = operations.stage(timeout=10)
        self.assertFalse(stage.operation_completed)

    def test_async_cancellation_stops_and_verifies_the_selected_child(self):
        import asyncio
        from hermes_installer.bootstrap_custody import BootstrapCancelled
        from hermes_installer.bootstrap_custody import RootSelectedHermesOperations

        class CancelClient:
            def __init__(self):
                self.stopped = False
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200, body=json.dumps({
                    "process_id": "e" * 32, "generation": "process-gen", "uid": 1234}).encode(),
                    receipt_id="start-cancel")
            def process_control_operation(self, operation, **kwargs):
                if operation == "process.status":
                    raise asyncio.CancelledError()
                if operation == "process.stop":
                    self.stopped = True
                    return SimpleNamespace(state="stopped", result={
                        "closed": True, "reap_state": "complete"})
                raise AssertionError(operation)

        client = CancelClient()
        operations = RootSelectedHermesOperations(BootstrapCustody(client), self.receipt())
        with self.assertRaises(BootstrapCancelled) as raised:
            operations.stage(timeout=10)
        self.assertTrue(client.stopped)
        self.assertTrue(raised.exception.cleanup_verified)
